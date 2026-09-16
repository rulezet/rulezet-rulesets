rule TTP_XOR_QUAD_CurrentVersionRun_20a2 {
  strings:
    $key_20a2 = { 73 cd [2] 57 c3 [2] 7c ef [2] 52 cd [2] 46 d6 [2] 49 cc [2] 57 d1 [2] 55 d0 [2] 4e d6 [2] 52 d1 [2] 4e fe }

  condition:
    any of them
}