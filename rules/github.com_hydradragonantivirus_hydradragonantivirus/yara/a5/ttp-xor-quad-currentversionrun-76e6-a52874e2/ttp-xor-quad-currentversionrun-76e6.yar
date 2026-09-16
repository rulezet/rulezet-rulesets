rule TTP_XOR_QUAD_CurrentVersionRun_76e6 {
  strings:
    $key_76e6 = { 25 89 [2] 01 87 [2] 2a ab [2] 04 89 [2] 10 92 [2] 1f 88 [2] 01 95 [2] 03 94 [2] 18 92 [2] 04 95 [2] 18 ba }

  condition:
    any of them
}