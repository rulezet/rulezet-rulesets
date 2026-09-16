rule IDDQD_God_Mode_Rule {
  meta:
    description = "Detects a wide array of cyber threats, from malware and ransomware to advanced persistent threats (APTs)"
    author      = "Florian Roth"
    reference   = "Internal Research - get a god mode rule set with THOR by Nextron Systems"
    date        = "2019-05-15"
    modified    = "2024-01-12"
    score       = 60

  strings:
    $ = "sekurlsa::logonpasswords" ascii wide nocase  
    $ = "ERROR kuhl" wide xor  
    $ = " -w hidden " ascii wide nocase  
    $ = "Koadic." ascii  
    $ = "ReflectiveLoader" fullword ascii wide xor  
    $ = "%s as %s\\%s: %d" ascii xor  
    $ = "[System.Convert]::FromBase64String(" ascii  
    $ = "/meterpreter/" ascii xor  
    $ = / -[eE][decoman]{0,41} ['"]?(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA|cgBlAG)/ ascii wide  
    $ = /  (sEt|SEt|SeT|sET|seT)  / ascii wide  
    $ = ");iex " nocase ascii wide  
    $ = "Nir Sofer" fullword wide  
    $ = "impacket." ascii  
    $ = /\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject)/ nocase  
    $ = "0000FEEDACDC}" ascii wide  
    $ = "vssadmin delete shadows" ascii nocase  
    $ = ".exe delete shadows" ascii nocase  
    $ = " shadowcopy delete" ascii wide nocase  
    $ = " delete catalog -quiet" ascii wide nocase  
    $ = "stratum+tcp://" ascii wide  
    $ = /\\(Debug|Release)\\(Key[lL]og|[Ii]nject|Steal|By[Pp]ass|Amsi|Dropper|Loader|CVE\-)/  
    $ = /(Dropper|Bypass|Injection|Potato)\.pdb/ nocase  
    $ = "Mozilla/5.0" xor(0x01-0xff) ascii wide  
    $ = "amsi.dllATVSH" ascii xor  
    $ = "BeaconJitter" xor  
    $ = "main.Merlin" ascii fullword  
    $ = "\x48\x83\xec\x50\x4d\x63\x68\x3c\x48\x89\x4d\x10" xor  
    $ = "}{0}\"-f " ascii wide  
    $ = "HISTORY=/dev/null" ascii  
    $ = " /tmp/x;" ascii  
    $ = /comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/  
    $ = "AmsiScanBuffer" ascii wide base64  
    $ = "AmsiScanBuffer" xor(0x01-0xff)  
    $ = "%%%%%%%%%%%######%%%#%%####%  &%%**#" ascii wide xor  

  condition:
    1 of them
}