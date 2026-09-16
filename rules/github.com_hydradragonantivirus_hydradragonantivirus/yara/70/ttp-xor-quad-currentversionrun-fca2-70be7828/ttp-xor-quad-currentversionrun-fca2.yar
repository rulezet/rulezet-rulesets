rule TTP_XOR_QUAD_CurrentVersionRun_fca2 {
  strings:
    $key_fca2 = { af cd [2] 8b c3 [2] a0 ef [2] 8e cd [2] 9a d6 [2] 95 cc [2] 8b d1 [2] 89 d0 [2] 92 d6 [2] 8e d1 [2] 92 fe }

  condition:
    any of them
}