rule _20160921_0a459915b243d5878c25fef831b72789_20160921_16200453422b_1786 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_66566a9bbc7830091a244fa6674b709b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash3       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"

  strings:
    $s1  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s2  = "turn \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3  = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f00" ascii
    $s4  = "turn \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5  = "nction f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){ret" ascii
    $s6  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Y" ascii
    $s7  = ";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f00" ascii
    $s8  = "tion f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){retur" ascii
    $s9  = "{return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"DIa\";})" ascii
    $s10 = "Gn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}