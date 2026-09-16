rule _20160921_4d4f88bcbe1d7c27849018b54d3401d0_20160921_8b0f3892ae56_5145 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash2       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"

  strings:
    $s1 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){retu" ascii
    $s2 = "\"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(funct" ascii
    $s3 = "turn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})()" ascii
    $s4 = "a\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"DNa\";})(),(function" ascii
    $s5 = "{return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}