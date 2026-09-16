rule TTP_XOR_QUAD_CurrentVersionRun_fde6 {
  strings:
    $key_fde6 = { ae 89 [2] 8a 87 [2] a1 ab [2] 8f 89 [2] 9b 92 [2] 94 88 [2] 8a 95 [2] 88 94 [2] 93 92 [2] 8f 95 [2] 93 ba }

  condition:
    any of them
}