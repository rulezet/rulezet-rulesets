rule TTP_XOR_QUAD_CurrentVersionRun_49a2 {
  strings:
    $key_49a2 = { 1a cd [2] 3e c3 [2] 15 ef [2] 3b cd [2] 2f d6 [2] 20 cc [2] 3e d1 [2] 3c d0 [2] 27 d6 [2] 3b d1 [2] 27 fe }

  condition:
    any of them
}