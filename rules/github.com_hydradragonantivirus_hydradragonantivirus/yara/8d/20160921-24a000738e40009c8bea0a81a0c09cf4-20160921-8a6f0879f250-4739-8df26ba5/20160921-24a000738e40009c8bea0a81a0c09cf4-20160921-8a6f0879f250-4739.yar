rule _20160921_24a000738e40009c8bea0a81a0c09cf4_20160921_8a6f0879f250_4739 {
  meta:
    description = "datamaliciousorder - from files 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s2 = "00(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl" ascii
    $s3 = "Gn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s4 = "(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "n\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}