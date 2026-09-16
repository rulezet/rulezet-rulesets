rule TTP_XOR_QUAD_CurrentVersionRun_1ce6 {
  strings:
    $key_1ce6 = { 4f 89 [2] 6b 87 [2] 40 ab [2] 6e 89 [2] 7a 92 [2] 75 88 [2] 6b 95 [2] 69 94 [2] 72 92 [2] 6e 95 [2] 72 ba }

  condition:
    any of them
}