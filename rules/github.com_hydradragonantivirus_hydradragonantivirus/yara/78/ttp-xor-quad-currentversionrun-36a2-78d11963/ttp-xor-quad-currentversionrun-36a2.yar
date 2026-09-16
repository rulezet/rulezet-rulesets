rule TTP_XOR_QUAD_CurrentVersionRun_36a2 {
  strings:
    $key_36a2 = { 65 cd [2] 41 c3 [2] 6a ef [2] 44 cd [2] 50 d6 [2] 5f cc [2] 41 d1 [2] 43 d0 [2] 58 d6 [2] 44 d1 [2] 58 fe }

  condition:
    any of them
}