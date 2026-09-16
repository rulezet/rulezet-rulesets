rule TTP_XOR_QUAD_CurrentVersionRun_22b3 {
  strings:
    $key_22b3 = { 71 dc [2] 55 d2 [2] 7e fe [2] 50 dc [2] 44 c7 [2] 4b dd [2] 55 c0 [2] 57 c1 [2] 4c c7 [2] 50 c0 [2] 4c ef }

  condition:
    any of them
}