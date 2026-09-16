rule TTP_XOR_QUAD_CurrentVersionRun_62b3 {
  strings:
    $key_62b3 = { 31 dc [2] 15 d2 [2] 3e fe [2] 10 dc [2] 04 c7 [2] 0b dd [2] 15 c0 [2] 17 c1 [2] 0c c7 [2] 10 c0 [2] 0c ef }

  condition:
    any of them
}