rule TTP_XOR_QUAD_CurrentVersionRun_1fe6 {
  strings:
    $key_1fe6 = { 4c 89 [2] 68 87 [2] 43 ab [2] 6d 89 [2] 79 92 [2] 76 88 [2] 68 95 [2] 6a 94 [2] 71 92 [2] 6d 95 [2] 71 ba }

  condition:
    any of them
}