rule TTP_XOR_QUAD_CurrentVersionRun_56a2 {
  strings:
    $key_56a2 = { 05 cd [2] 21 c3 [2] 0a ef [2] 24 cd [2] 30 d6 [2] 3f cc [2] 21 d1 [2] 23 d0 [2] 38 d6 [2] 24 d1 [2] 38 fe }

  condition:
    any of them
}