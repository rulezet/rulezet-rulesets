rule TTP_XOR_QUAD_CurrentVersionRun_1ca2 {
  strings:
    $key_1ca2 = { 4f cd [2] 6b c3 [2] 40 ef [2] 6e cd [2] 7a d6 [2] 75 cc [2] 6b d1 [2] 69 d0 [2] 72 d6 [2] 6e d1 [2] 72 fe }

  condition:
    any of them
}