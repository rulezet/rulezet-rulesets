rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_f232e0ba2dbd_1189 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"
    hash3       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash4       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "\"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(functi" ascii
    $s2  = "n \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3  = "rn \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(f" ascii
    $s4  = "on f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"" ascii
    $s5  = "on f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"" ascii
    $s6  = ",(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s7  = "000(){return \"YTp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s8  = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(fu" ascii
    $s9  = "),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(" ascii
    $s10 = "tion f000(){return \"DAp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s11 = ",(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s12 = "0(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn" ascii
    $s13 = "unction f000(){return \"TKl\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s14 = "})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f00" ascii
    $s15 = "),(function f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){" ascii
    $s16 = "f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZI" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}