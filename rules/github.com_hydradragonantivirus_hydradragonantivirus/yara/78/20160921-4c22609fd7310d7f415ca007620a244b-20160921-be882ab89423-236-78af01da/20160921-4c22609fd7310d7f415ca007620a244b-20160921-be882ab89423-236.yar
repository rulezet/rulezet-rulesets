rule _20160921_4c22609fd7310d7f415ca007620a244b_20160921_be882ab89423_236 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash2       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"

  strings:
    $s1  = "ion f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2  = "{return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3  = "on f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(" ascii
    $s5  = "f000(){return \"ZFe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw" ascii
    $s6  = "(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})" ascii
    $s7  = ")(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f00" ascii
    $s8  = " f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"U" ascii
    $s9  = "on f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(" ascii
    $s11 = "g\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s12 = " f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv" ascii
    $s13 = "Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s14 = " \"Kw\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s15 = "return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()" ascii
    $s16 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii
    $s17 = "\"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s18 = "n f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"" ascii
    $s19 = "Vb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function" ascii
    $s20 = "ion f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}