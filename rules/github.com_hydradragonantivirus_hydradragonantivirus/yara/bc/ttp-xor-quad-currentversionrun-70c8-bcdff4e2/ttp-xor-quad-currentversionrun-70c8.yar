rule TTP_XOR_QUAD_CurrentVersionRun_70c8 {
  strings:
    $key_70c8 = { 23 a7 [2] 07 a9 [2] 2c 85 [2] 02 a7 [2] 16 bc [2] 19 a6 [2] 07 bb [2] 05 ba [2] 1e bc [2] 02 bb [2] 1e 94 }

  condition:
    any of them
}