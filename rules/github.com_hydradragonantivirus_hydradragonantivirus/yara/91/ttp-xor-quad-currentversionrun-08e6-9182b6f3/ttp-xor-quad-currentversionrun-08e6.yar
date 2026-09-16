rule TTP_XOR_QUAD_CurrentVersionRun_08e6 {
  strings:
    $key_08e6 = { 5b 89 [2] 7f 87 [2] 54 ab [2] 7a 89 [2] 6e 92 [2] 61 88 [2] 7f 95 [2] 7d 94 [2] 66 92 [2] 7a 95 [2] 66 ba }

  condition:
    any of them
}