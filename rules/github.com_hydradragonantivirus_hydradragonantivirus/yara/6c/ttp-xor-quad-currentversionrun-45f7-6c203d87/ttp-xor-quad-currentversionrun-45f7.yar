rule TTP_XOR_QUAD_CurrentVersionRun_45f7 {
  strings:
    $key_45f7 = { 16 98 [2] 32 96 [2] 19 ba [2] 37 98 [2] 23 83 [2] 2c 99 [2] 32 84 [2] 30 85 [2] 2b 83 [2] 37 84 [2] 2b ab }

  condition:
    any of them
}