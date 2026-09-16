rule _20160921_61ffae07802bf5013fbbf8f137c827c3_20160921_da68ef3a64fe_2478 {
  meta:
    description = "datamaliciousorder - from files 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1 = "})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f00" ascii
    $s2 = "n f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TR" ascii
    $s3 = "{return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s4 = "on f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Q" ascii
    $s5 = " f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"" ascii
    $s6 = " \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s7 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s8 = "(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}