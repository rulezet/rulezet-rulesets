rule TTP_XOR_QUAD_CurrentVersionRun_26e6 {
  strings:
    $key_26e6 = { 75 89 [2] 51 87 [2] 7a ab [2] 54 89 [2] 40 92 [2] 4f 88 [2] 51 95 [2] 53 94 [2] 48 92 [2] 54 95 [2] 48 ba }

  condition:
    any of them
}