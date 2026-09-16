rule TTP_XOR_QUAD_CurrentVersionRun_39e6 {
  strings:
    $key_39e6 = { 6a 89 [2] 4e 87 [2] 65 ab [2] 4b 89 [2] 5f 92 [2] 50 88 [2] 4e 95 [2] 4c 94 [2] 57 92 [2] 4b 95 [2] 57 ba }

  condition:
    any of them
}