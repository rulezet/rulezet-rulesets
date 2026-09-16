rule TTP_XOR_QUAD_CurrentVersionRun_05e6 {
  strings:
    $key_05e6 = { 56 89 [2] 72 87 [2] 59 ab [2] 77 89 [2] 63 92 [2] 6c 88 [2] 72 95 [2] 70 94 [2] 6b 92 [2] 77 95 [2] 6b ba }

  condition:
    any of them
}