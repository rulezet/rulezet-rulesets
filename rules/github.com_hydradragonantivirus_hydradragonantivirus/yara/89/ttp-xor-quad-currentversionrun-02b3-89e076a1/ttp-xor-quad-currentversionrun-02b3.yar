rule TTP_XOR_QUAD_CurrentVersionRun_02b3 {
  strings:
    $key_02b3 = { 51 dc [2] 75 d2 [2] 5e fe [2] 70 dc [2] 64 c7 [2] 6b dd [2] 75 c0 [2] 77 c1 [2] 6c c7 [2] 70 c0 [2] 6c ef }

  condition:
    any of them
}