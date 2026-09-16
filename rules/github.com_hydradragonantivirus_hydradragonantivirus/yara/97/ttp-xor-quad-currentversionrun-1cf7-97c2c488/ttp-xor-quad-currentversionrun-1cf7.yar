rule TTP_XOR_QUAD_CurrentVersionRun_1cf7 {
  strings:
    $key_1cf7 = { 4f 98 [2] 6b 96 [2] 40 ba [2] 6e 98 [2] 7a 83 [2] 75 99 [2] 6b 84 [2] 69 85 [2] 72 83 [2] 6e 84 [2] 72 ab }

  condition:
    any of them
}