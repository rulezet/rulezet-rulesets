rule TTP_XOR_QUAD_CurrentVersionRun_3ca2 {
  strings:
    $key_3ca2 = { 6f cd [2] 4b c3 [2] 60 ef [2] 4e cd [2] 5a d6 [2] 55 cc [2] 4b d1 [2] 49 d0 [2] 52 d6 [2] 4e d1 [2] 52 fe }

  condition:
    any of them
}