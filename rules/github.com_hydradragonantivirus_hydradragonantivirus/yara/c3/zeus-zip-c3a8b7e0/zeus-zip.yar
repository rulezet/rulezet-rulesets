rule zeus_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 19, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "botnet_bots.php"
        $txt4 = "botnet_scripts.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}