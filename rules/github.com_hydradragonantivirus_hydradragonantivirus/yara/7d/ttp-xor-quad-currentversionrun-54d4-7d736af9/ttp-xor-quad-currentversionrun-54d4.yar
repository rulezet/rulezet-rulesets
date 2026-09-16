rule TTP_XOR_QUAD_CurrentVersionRun_54d4 {
  strings:
    $key_54d4 = { 07 bb [2] 23 b5 [2] 08 99 [2] 26 bb [2] 32 a0 [2] 3d ba [2] 23 a7 [2] 21 a6 [2] 3a a0 [2] 26 a7 [2] 3a 88 }

  condition:
    any of them
}