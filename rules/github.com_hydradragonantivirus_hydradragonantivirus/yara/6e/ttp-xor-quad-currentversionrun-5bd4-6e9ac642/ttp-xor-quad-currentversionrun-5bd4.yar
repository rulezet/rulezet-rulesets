rule TTP_XOR_QUAD_CurrentVersionRun_5bd4 {
  strings:
    $key_5bd4 = { 08 bb [2] 2c b5 [2] 07 99 [2] 29 bb [2] 3d a0 [2] 32 ba [2] 2c a7 [2] 2e a6 [2] 35 a0 [2] 29 a7 [2] 35 88 }

  condition:
    any of them
}