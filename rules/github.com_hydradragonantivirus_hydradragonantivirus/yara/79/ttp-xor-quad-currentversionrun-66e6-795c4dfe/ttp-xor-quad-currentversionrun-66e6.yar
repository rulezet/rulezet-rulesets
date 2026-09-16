rule TTP_XOR_QUAD_CurrentVersionRun_66e6 {
  strings:
    $key_66e6 = { 35 89 [2] 11 87 [2] 3a ab [2] 14 89 [2] 00 92 [2] 0f 88 [2] 11 95 [2] 13 94 [2] 08 92 [2] 14 95 [2] 08 ba }

  condition:
    any of them
}