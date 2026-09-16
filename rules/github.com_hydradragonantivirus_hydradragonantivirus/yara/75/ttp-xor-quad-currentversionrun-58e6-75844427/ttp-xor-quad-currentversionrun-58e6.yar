rule TTP_XOR_QUAD_CurrentVersionRun_58e6 {
  strings:
    $key_58e6 = { 0b 89 [2] 2f 87 [2] 04 ab [2] 2a 89 [2] 3e 92 [2] 31 88 [2] 2f 95 [2] 2d 94 [2] 36 92 [2] 2a 95 [2] 36 ba }

  condition:
    any of them
}