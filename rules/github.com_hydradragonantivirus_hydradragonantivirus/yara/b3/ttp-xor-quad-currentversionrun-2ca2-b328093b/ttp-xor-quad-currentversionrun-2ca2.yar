rule TTP_XOR_QUAD_CurrentVersionRun_2ca2 {
  strings:
    $key_2ca2 = { 7f cd [2] 5b c3 [2] 70 ef [2] 5e cd [2] 4a d6 [2] 45 cc [2] 5b d1 [2] 59 d0 [2] 42 d6 [2] 5e d1 [2] 42 fe }

  condition:
    any of them
}