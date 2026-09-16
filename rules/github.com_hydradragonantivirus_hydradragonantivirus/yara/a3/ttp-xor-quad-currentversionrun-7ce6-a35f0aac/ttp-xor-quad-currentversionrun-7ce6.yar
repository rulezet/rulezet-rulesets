rule TTP_XOR_QUAD_CurrentVersionRun_7ce6 {
  strings:
    $key_7ce6 = { 2f 89 [2] 0b 87 [2] 20 ab [2] 0e 89 [2] 1a 92 [2] 15 88 [2] 0b 95 [2] 09 94 [2] 12 92 [2] 0e 95 [2] 12 ba }

  condition:
    any of them
}