rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_5501 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash4       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "h\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s2 = "unction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s3 = "{return \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})" ascii
    $s4 = " f000(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"G" ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wy\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}