rule TTP_XOR_QUAD_CurrentVersionRun_f2e6 {
  strings:
    $key_f2e6 = { a1 89 [2] 85 87 [2] ae ab [2] 80 89 [2] 94 92 [2] 9b 88 [2] 85 95 [2] 87 94 [2] 9c 92 [2] 80 95 [2] 9c ba }

  condition:
    any of them
}