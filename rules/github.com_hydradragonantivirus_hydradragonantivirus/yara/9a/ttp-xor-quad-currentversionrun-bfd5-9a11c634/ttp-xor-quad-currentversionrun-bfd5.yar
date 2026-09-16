rule TTP_XOR_QUAD_CurrentVersionRun_bfd5 {
  strings:
    $key_bfd5 = { ec ba [2] c8 b4 [2] e3 98 [2] cd ba [2] d9 a1 [2] d6 bb [2] c8 a6 [2] ca a7 [2] d1 a1 [2] cd a6 [2] d1 89 }

  condition:
    any of them
}