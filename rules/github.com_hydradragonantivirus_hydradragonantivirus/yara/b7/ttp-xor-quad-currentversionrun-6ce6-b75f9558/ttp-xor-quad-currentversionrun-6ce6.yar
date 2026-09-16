rule TTP_XOR_QUAD_CurrentVersionRun_6ce6 {
  strings:
    $key_6ce6 = { 3f 89 [2] 1b 87 [2] 30 ab [2] 1e 89 [2] 0a 92 [2] 05 88 [2] 1b 95 [2] 19 94 [2] 02 92 [2] 1e 95 [2] 02 ba }

  condition:
    any of them
}