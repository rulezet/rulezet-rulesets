rule TTP_XOR_QUAD_CurrentVersionRun_22e6 {
  strings:
    $key_22e6 = { 71 89 [2] 55 87 [2] 7e ab [2] 50 89 [2] 44 92 [2] 4b 88 [2] 55 95 [2] 57 94 [2] 4c 92 [2] 50 95 [2] 4c ba }

  condition:
    any of them
}