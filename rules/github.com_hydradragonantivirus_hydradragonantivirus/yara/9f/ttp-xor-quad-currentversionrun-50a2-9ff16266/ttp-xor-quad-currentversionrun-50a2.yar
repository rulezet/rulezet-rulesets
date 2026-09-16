rule TTP_XOR_QUAD_CurrentVersionRun_50a2 {
  strings:
    $key_50a2 = { 03 cd [2] 27 c3 [2] 0c ef [2] 22 cd [2] 36 d6 [2] 39 cc [2] 27 d1 [2] 25 d0 [2] 3e d6 [2] 22 d1 [2] 3e fe }

  condition:
    any of them
}