rule TTP_XOR_QUAD_CurrentVersionRun_58a2 {
  strings:
    $key_58a2 = { 0b cd [2] 2f c3 [2] 04 ef [2] 2a cd [2] 3e d6 [2] 31 cc [2] 2f d1 [2] 2d d0 [2] 36 d6 [2] 2a d1 [2] 36 fe }

  condition:
    any of them
}