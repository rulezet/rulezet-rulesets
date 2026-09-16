rule TTP_XOR_QUAD_CurrentVersionRun_1de6 {
  strings:
    $key_1de6 = { 4e 89 [2] 6a 87 [2] 41 ab [2] 6f 89 [2] 7b 92 [2] 74 88 [2] 6a 95 [2] 68 94 [2] 73 92 [2] 6f 95 [2] 73 ba }

  condition:
    any of them
}