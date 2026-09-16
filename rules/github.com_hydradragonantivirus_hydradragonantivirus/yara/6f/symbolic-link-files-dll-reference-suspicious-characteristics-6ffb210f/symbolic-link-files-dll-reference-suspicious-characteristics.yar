rule Symbolic_Link_Files_DLL_Reference_Suspicious_Characteristics {
  meta:
    Author      = "InQuest Labs"
    URL         = "https://github.com/InQuest/yara-rules/blob/master/Symbolic_Link_Files_DLL_Reference_Suspicious_Characteristics.rule"
    Description = "This signature detects Microsoft Excel Symbolic Link (SLK) files that contain reference to DLL files.  While not inherently malicious, these SLK files can be used used by attackers to evade detection and deliver malicious payloads."
    References  = "https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format/"

  strings:
    $magic = "ID;P"

    $re1 = /\x0aO;E[\r\n]/ nocase
    

    $re2 = /\x0a[A-Z];[^\x0a]+E(Call|Open)\x28[ \t]*['"](kernel32|user32|Shell32|urlmon|RunDll|wininet)(\.dll)?[ \t]*['"][ \t]*,[^\x29\x0a]*\x29/ nocase
  
  

  condition:
    $magic in (0..100) and all of ($re*)
}