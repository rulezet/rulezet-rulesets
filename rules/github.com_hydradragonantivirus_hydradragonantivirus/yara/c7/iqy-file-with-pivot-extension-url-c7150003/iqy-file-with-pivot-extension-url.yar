rule IQY_File_With_Pivot_Extension_URL
{
    meta:
        Author = "InQuest Labs"
        Reference = "http://blog.inquest.net/blog/2018/08/23/hunting-iqy-files-with-yara/"
        Description = "Detect Excel IQY files with URLs that contain commonly used malicious file extensions that may act as a pivot to a secondary stage."
        Severity = "9"
    strings:
        
         $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        

        $url = /https?:\/\/[\w\.\/]+\.(scr|exe|hta|vbs|ps1|bat|dat|rar|zip|ace)/ nocase

    condition:
        $web at 0 and $url
}