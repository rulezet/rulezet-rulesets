rule TTP_XOR_QUAD_CurrentVersionRun_6ed5 {
  strings:
    $key_6ed5 = { 3d ba [2] 19 b4 [2] 32 98 [2] 1c ba [2] 08 a1 [2] 07 bb [2] 19 a6 [2] 1b a7 [2] 00 a1 [2] 1c a6 [2] 00 89 }

  condition:
    any of them
}