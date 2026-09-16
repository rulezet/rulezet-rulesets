rule TTP_XOR_QUAD_CurrentVersionRun_2ae6 {
  strings:
    $key_2ae6 = { 79 89 [2] 5d 87 [2] 76 ab [2] 58 89 [2] 4c 92 [2] 43 88 [2] 5d 95 [2] 5f 94 [2] 44 92 [2] 58 95 [2] 44 ba }

  condition:
    any of them
}