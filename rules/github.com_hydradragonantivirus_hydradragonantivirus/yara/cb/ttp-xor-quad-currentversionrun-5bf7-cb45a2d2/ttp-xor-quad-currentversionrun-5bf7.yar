rule TTP_XOR_QUAD_CurrentVersionRun_5bf7 {
  strings:
    $key_5bf7 = { 08 98 [2] 2c 96 [2] 07 ba [2] 29 98 [2] 3d 83 [2] 32 99 [2] 2c 84 [2] 2e 85 [2] 35 83 [2] 29 84 [2] 35 ab }

  condition:
    any of them
}