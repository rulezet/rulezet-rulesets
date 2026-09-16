rule TTP_XOR_QUAD_CurrentVersionRun_48a2 {
  strings:
    $key_48a2 = { 1b cd [2] 3f c3 [2] 14 ef [2] 3a cd [2] 2e d6 [2] 21 cc [2] 3f d1 [2] 3d d0 [2] 26 d6 [2] 3a d1 [2] 26 fe }

  condition:
    any of them
}