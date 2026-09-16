rule TTP_XOR_QUAD_CurrentVersionRun_7cf7 {
  strings:
    $key_7cf7 = { 2f 98 [2] 0b 96 [2] 20 ba [2] 0e 98 [2] 1a 83 [2] 15 99 [2] 0b 84 [2] 09 85 [2] 12 83 [2] 0e 84 [2] 12 ab }

  condition:
    any of them
}