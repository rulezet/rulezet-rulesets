rule TTP_XOR_QUAD_CurrentVersionRun_4aa2 {
  strings:
    $key_4aa2 = { 19 cd [2] 3d c3 [2] 16 ef [2] 38 cd [2] 2c d6 [2] 23 cc [2] 3d d1 [2] 3f d0 [2] 24 d6 [2] 38 d1 [2] 24 fe }

  condition:
    any of them
}