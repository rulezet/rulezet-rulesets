rule TTP_XOR_QUAD_CurrentVersionRun_68a2 {
  strings:
    $key_68a2 = { 3b cd [2] 1f c3 [2] 34 ef [2] 1a cd [2] 0e d6 [2] 01 cc [2] 1f d1 [2] 1d d0 [2] 06 d6 [2] 1a d1 [2] 06 fe }

  condition:
    any of them
}