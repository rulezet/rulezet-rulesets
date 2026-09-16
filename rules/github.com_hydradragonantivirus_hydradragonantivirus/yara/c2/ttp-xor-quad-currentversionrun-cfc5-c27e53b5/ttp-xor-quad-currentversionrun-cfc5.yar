rule TTP_XOR_QUAD_CurrentVersionRun_cfc5 {
  strings:
    $key_cfc5 = { 9c aa [2] b8 a4 [2] 93 88 [2] bd aa [2] a9 b1 [2] a6 ab [2] b8 b6 [2] ba b7 [2] a1 b1 [2] bd b6 [2] a1 99 }

  condition:
    any of them
}