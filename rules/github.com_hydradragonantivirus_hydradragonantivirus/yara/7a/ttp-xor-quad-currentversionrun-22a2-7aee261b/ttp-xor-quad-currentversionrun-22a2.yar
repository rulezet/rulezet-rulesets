rule TTP_XOR_QUAD_CurrentVersionRun_22a2 {
  strings:
    $key_22a2 = { 71 cd [2] 55 c3 [2] 7e ef [2] 50 cd [2] 44 d6 [2] 4b cc [2] 55 d1 [2] 57 d0 [2] 4c d6 [2] 50 d1 [2] 4c fe }

  condition:
    any of them
}