rule TTP_XOR_QUAD_CurrentVersionRun_70a2 {
  strings:
    $key_70a2 = { 23 cd [2] 07 c3 [2] 2c ef [2] 02 cd [2] 16 d6 [2] 19 cc [2] 07 d1 [2] 05 d0 [2] 1e d6 [2] 02 d1 [2] 1e fe }

  condition:
    any of them
}