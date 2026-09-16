rule TTP_XOR_QUAD_CurrentVersionRun_28e6 {
  strings:
    $key_28e6 = { 7b 89 [2] 5f 87 [2] 74 ab [2] 5a 89 [2] 4e 92 [2] 41 88 [2] 5f 95 [2] 5d 94 [2] 46 92 [2] 5a 95 [2] 46 ba }

  condition:
    any of them
}