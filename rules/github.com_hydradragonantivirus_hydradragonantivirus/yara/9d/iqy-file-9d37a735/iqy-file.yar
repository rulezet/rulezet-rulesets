rule IQY_File
{
    meta:
        Author = "InQuest Labs"
        Website = "http://blog.inquest.net/blog/2018/08/23/hunting-iqy-files-with-yara/"
        Description = "Detects all Excel IQY files by identifying the WEB 'magic' on the first line and also includes any URL."
        Severity = "0"

   strings:
        
        $web = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

    condition:
        $web at 0 and $url
}