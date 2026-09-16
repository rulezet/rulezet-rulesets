rule TTP_XOR_QUAD_CurrentVersionRun_e8e6 {
  strings:
    $key_e8e6 = { bb 89 [2] 9f 87 [2] b4 ab [2] 9a 89 [2] 8e 92 [2] 81 88 [2] 9f 95 [2] 9d 94 [2] 86 92 [2] 9a 95 [2] 86 ba }

  condition:
    any of them
}