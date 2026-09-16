rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160921_86f41d8c8324_420 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_be923844637026740bc9e5a4aad21ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash3       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"

  strings:
    $s1  = "rn \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(fu" ascii
    $s2  = ";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f0" ascii
    $s3  = "00(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";}" ascii
    $s4  = "tion f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s5  = "ion f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii
    $s6  = "l\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s7  = " \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s8  = "){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})()" ascii
    $s10 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f00" ascii
    $s11 = "0(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";}" ascii
    $s12 = "return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})()," ascii
    $s13 = "){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})" ascii
    $s14 = "Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function" ascii
    $s15 = "return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})()," ascii
    $s16 = "ction f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s17 = "KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s18 = "turn \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s19 = "rn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(fu" ascii
    $s20 = "00(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}