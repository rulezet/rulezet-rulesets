rule TTP_XOR_QUAD_CurrentVersionRun_d0e7 {
  strings:
    $key_d0e7 = { 83 88 [2] a7 86 [2] 8c aa [2] a2 88 [2] b6 93 [2] b9 89 [2] a7 94 [2] a5 95 [2] be 93 [2] a2 94 [2] be bb }

  condition:
    any of them
}