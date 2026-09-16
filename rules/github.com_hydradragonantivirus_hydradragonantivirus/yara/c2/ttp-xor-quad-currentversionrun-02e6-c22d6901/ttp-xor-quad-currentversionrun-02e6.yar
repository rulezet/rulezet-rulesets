rule TTP_XOR_QUAD_CurrentVersionRun_02e6 {
  strings:
    $key_02e6 = { 51 89 [2] 75 87 [2] 5e ab [2] 70 89 [2] 64 92 [2] 6b 88 [2] 75 95 [2] 77 94 [2] 6c 92 [2] 70 95 [2] 6c ba }

  condition:
    any of them
}