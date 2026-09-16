rule TTP_XOR_QUAD_CurrentVersionRun_3de6 {
  strings:
    $key_3de6 = { 6e 89 [2] 4a 87 [2] 61 ab [2] 4f 89 [2] 5b 92 [2] 54 88 [2] 4a 95 [2] 48 94 [2] 53 92 [2] 4f 95 [2] 53 ba }

  condition:
    any of them
}