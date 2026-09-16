rule TTP_XOR_QUAD_CurrentVersionRun_72c8 {
  strings:
    $key_72c8 = { 21 a7 [2] 05 a9 [2] 2e 85 [2] 00 a7 [2] 14 bc [2] 1b a6 [2] 05 bb [2] 07 ba [2] 1c bc [2] 00 bb [2] 1c 94 }

  condition:
    any of them
}