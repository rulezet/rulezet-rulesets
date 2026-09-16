rule TTP_XOR_QUAD_CurrentVersionRun_10a2 {
  strings:
    $key_10a2 = { 43 cd [2] 67 c3 [2] 4c ef [2] 62 cd [2] 76 d6 [2] 79 cc [2] 67 d1 [2] 65 d0 [2] 7e d6 [2] 62 d1 [2] 7e fe }

  condition:
    any of them
}