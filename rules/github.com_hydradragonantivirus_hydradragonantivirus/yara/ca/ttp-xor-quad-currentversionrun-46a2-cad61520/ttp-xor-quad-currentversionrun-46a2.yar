rule TTP_XOR_QUAD_CurrentVersionRun_46a2 {
  strings:
    $key_46a2 = { 15 cd [2] 31 c3 [2] 1a ef [2] 34 cd [2] 20 d6 [2] 2f cc [2] 31 d1 [2] 33 d0 [2] 28 d6 [2] 34 d1 [2] 28 fe }

  condition:
    any of them
}