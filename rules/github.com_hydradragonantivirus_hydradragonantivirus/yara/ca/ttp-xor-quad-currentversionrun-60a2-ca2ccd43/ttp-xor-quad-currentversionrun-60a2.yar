rule TTP_XOR_QUAD_CurrentVersionRun_60a2 {
  strings:
    $key_60a2 = { 33 cd [2] 17 c3 [2] 3c ef [2] 12 cd [2] 06 d6 [2] 09 cc [2] 17 d1 [2] 15 d0 [2] 0e d6 [2] 12 d1 [2] 0e fe }

  condition:
    any of them
}