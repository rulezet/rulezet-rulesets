rule TTP_XOR_QUAD_CurrentVersionRun_72b3 {
  strings:
    $key_72b3 = { 21 dc [2] 05 d2 [2] 2e fe [2] 00 dc [2] 14 c7 [2] 1b dd [2] 05 c0 [2] 07 c1 [2] 1c c7 [2] 00 c0 [2] 1c ef }

  condition:
    any of them
}