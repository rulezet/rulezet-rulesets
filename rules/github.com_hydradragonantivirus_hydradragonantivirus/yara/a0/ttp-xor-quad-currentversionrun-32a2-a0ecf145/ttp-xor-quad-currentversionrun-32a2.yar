rule TTP_XOR_QUAD_CurrentVersionRun_32a2 {
  strings:
    $key_32a2 = { 61 cd [2] 45 c3 [2] 6e ef [2] 40 cd [2] 54 d6 [2] 5b cc [2] 45 d1 [2] 47 d0 [2] 5c d6 [2] 40 d1 [2] 5c fe }

  condition:
    any of them
}