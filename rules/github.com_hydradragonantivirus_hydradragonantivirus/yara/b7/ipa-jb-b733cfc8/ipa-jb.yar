rule ipa_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"
        
    strings:
        $zip = "PK"
        $import1 = ".app/jailbreak" nocase
        $import2 = ".app/patch" nocase
 
    condition:
        $zip at 0 and any of ( $import* )
}