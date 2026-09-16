rule TTP_XOR_QUAD_CurrentVersionRun_cdcb {
  strings:
    $key_cdcb = { 9e a4 [2] ba aa [2] 91 86 [2] bf a4 [2] ab bf [2] a4 a5 [2] ba b8 [2] b8 b9 [2] a3 bf [2] bf b8 [2] a3 97 }

  condition:
    any of them
}