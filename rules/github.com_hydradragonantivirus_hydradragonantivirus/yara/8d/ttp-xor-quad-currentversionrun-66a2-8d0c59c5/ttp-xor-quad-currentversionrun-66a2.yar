rule TTP_XOR_QUAD_CurrentVersionRun_66a2 {
  strings:
    $key_66a2 = { 35 cd [2] 11 c3 [2] 3a ef [2] 14 cd [2] 00 d6 [2] 0f cc [2] 11 d1 [2] 13 d0 [2] 08 d6 [2] 14 d1 [2] 08 fe }

  condition:
    any of them
}