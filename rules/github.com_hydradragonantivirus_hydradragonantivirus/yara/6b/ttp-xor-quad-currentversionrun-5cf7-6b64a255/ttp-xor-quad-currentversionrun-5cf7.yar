rule TTP_XOR_QUAD_CurrentVersionRun_5cf7 {
  strings:
    $key_5cf7 = { 0f 98 [2] 2b 96 [2] 00 ba [2] 2e 98 [2] 3a 83 [2] 35 99 [2] 2b 84 [2] 29 85 [2] 32 83 [2] 2e 84 [2] 32 ab }

  condition:
    any of them
}