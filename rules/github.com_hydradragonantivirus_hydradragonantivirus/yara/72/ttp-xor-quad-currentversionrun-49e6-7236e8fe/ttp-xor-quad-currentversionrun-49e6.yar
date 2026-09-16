rule TTP_XOR_QUAD_CurrentVersionRun_49e6 {
  strings:
    $key_49e6 = { 1a 89 [2] 3e 87 [2] 15 ab [2] 3b 89 [2] 2f 92 [2] 20 88 [2] 3e 95 [2] 3c 94 [2] 27 92 [2] 3b 95 [2] 27 ba }

  condition:
    any of them
}