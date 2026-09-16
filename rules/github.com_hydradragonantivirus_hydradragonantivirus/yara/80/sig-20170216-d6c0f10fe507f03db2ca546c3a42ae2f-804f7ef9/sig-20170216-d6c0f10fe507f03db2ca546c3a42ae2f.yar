rule sig_20170216_d6c0f10fe507f03db2ca546c3a42ae2f {
  meta:
    description = "datamaliciousorder - file 20170216_d6c0f10fe507f03db2ca546c3a42ae2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7dbcb30ab2df287b1d4cfabf5188d5bb3a2bb251c4a73ee8588b39bd030321f"

  strings:
    $s1  = "var pzumiki = [Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, \"cmd.\", Date, Date, Date, Date, Date][11];" fullword ascii
    $s2  = "var ypdark = [Date, Date, Date, Date, \"spir\", Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date][4];" fullword ascii
    $s3  = "uhalxutc[afizzuqxyg]([Date, Date, Date, Date, Date, Date, Date, pzumiki + girugp + ufotqod + yvoba + ycumir + nwokvurk + igihfu " ascii
    $s4  = "zykd + rato + sididu + dguvwo + isyle + iddogm + efxonwapx + lwizi + ezinoc, Date, Date, Date, Date, Date, Date, Date, Date, Dat" ascii
    $s5  = "var gejist = [\"  -'\", Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date][0];" fullword ascii
    $s6  = "uhalxutc[afizzuqxyg]([Date, Date, Date, Date, Date, Date, Date, pzumiki + girugp + ufotqod + yvoba + ycumir + nwokvurk + igihfu " ascii
    $s7  = "var itmuzcyvqup = [Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, typeof XMLHttpRequest == \"undefined\", Dat" ascii
    $s8  = "var itmuzcyvqup = [Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, typeof XMLHttpRequest == \"undefined\", Dat" ascii
    $s9  = "var lonti = [Date, Date, Date, Date, Date, Date, Date, Date, \".Dow\", Date, Date, Date, Date, Date, Date, Date, Date][8];" fullword ascii
    $s10 = "var ixaxt = [Date, Date, \"j+$c\", Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date][2];" ascii
    $s11 = "var zropgy = [Date, Date, Date, Date, \"jdyt\", Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date][4]" ascii
    $s12 = "var xbyjeh = [Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, \"t-Ex\", Date, Date, Date, Date][10];" fullword ascii
    $s13 = "var cciwuct = [Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, \"top'\", Date][1" ascii
    $s14 = "var gitpunt = [Date, \"vzem\", Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date][1];" fullword ascii
    $s15 = "var isyle = [Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, \"+$bu\", Date][16]" ascii
    $s16 = "var fincyk = null;" fullword ascii
    $s17 = "var nekqonu = [Date, Date, Date, Date, Date, Date, \"apr+\", Date, Date, Date, Date, Date, Date, Date, Date, Date][6];" fullword ascii
    $s18 = "var efxonwapx = [\"usfi\", Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date, Date]" ascii
    $s19 = "var qvyffapa = [Date, Date, Date, Date, Date, Date, Date, Date, Date, \"edu+\", Date, Date, Date, Date, Date, Date][9];" fullword ascii
    $s20 = "var iplofdo = [Date, Date, Date, Date, Date, Date, Date, \"kyrg\", Date, Date, Date, Date, Date, Date, Date, Date][7];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}