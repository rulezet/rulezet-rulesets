rule TTP_XOR_QUAD_CurrentVersionRun_0ce6 {
  strings:
    $key_0ce6 = { 5f 89 [2] 7b 87 [2] 50 ab [2] 7e 89 [2] 6a 92 [2] 65 88 [2] 7b 95 [2] 79 94 [2] 62 92 [2] 7e 95 [2] 62 ba }

  condition:
    any of them
}