rule TTP_XOR_QUAD_CurrentVersionRun_12a2 {
  strings:
    $key_12a2 = { 41 cd [2] 65 c3 [2] 4e ef [2] 60 cd [2] 74 d6 [2] 7b cc [2] 65 d1 [2] 67 d0 [2] 7c d6 [2] 60 d1 [2] 7c fe }

  condition:
    any of them
}