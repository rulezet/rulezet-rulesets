rule TTP_XOR_QUAD_CurrentVersionRun_69a2 {
  strings:
    $key_69a2 = { 3a cd [2] 1e c3 [2] 35 ef [2] 1b cd [2] 0f d6 [2] 00 cc [2] 1e d1 [2] 1c d0 [2] 07 d6 [2] 1b d1 [2] 07 fe }

  condition:
    any of them
}