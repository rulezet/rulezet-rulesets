rule TTP_XOR_QUAD_CurrentVersionRun_1ee6 {
  strings:
    $key_1ee6 = { 4d 89 [2] 69 87 [2] 42 ab [2] 6c 89 [2] 78 92 [2] 77 88 [2] 69 95 [2] 6b 94 [2] 70 92 [2] 6c 95 [2] 70 ba }

  condition:
    any of them
}