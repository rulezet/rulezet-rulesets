rule TTP_XOR_QUAD_CurrentVersionRun_1ae6 {
  strings:
    $key_1ae6 = { 49 89 [2] 6d 87 [2] 46 ab [2] 68 89 [2] 7c 92 [2] 73 88 [2] 6d 95 [2] 6f 94 [2] 74 92 [2] 68 95 [2] 74 ba }

  condition:
    any of them
}