rule TTP_XOR_QUAD_CurrentVersionRun_f2a2 {
  strings:
    $key_f2a2 = { a1 cd [2] 85 c3 [2] ae ef [2] 80 cd [2] 94 d6 [2] 9b cc [2] 85 d1 [2] 87 d0 [2] 9c d6 [2] 80 d1 [2] 9c fe }

  condition:
    any of them
}