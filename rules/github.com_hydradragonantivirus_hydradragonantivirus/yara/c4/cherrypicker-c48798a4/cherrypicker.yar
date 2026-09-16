rule cherryPicker
{
    meta:
        author = "Trustwave SpiderLabs"
        date = "2015-11-17"
        description = "Used to detect Cherry Picker malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/?page=1&year=0&month=0"
    strings:
        $string1 = "srch1mutex" nocase
        $string2 = "SYNC32TOOLBOX" nocase
        $string3 = "kb852310.dll"
        $config1 = "[config]" nocase
        $config2 = "timeout"
        $config3 = "r_cnt"
        $config4 = "f_passive"
        $config5 = "prlog"
    condition:
        any of ($string*) or all of ($config*)

}