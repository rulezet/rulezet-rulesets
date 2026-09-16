rule TTP_XOR_QUAD_CurrentVersionRun_2aa2 {
  strings:
    $key_2aa2 = { 79 cd [2] 5d c3 [2] 76 ef [2] 58 cd [2] 4c d6 [2] 43 cc [2] 5d d1 [2] 5f d0 [2] 44 d6 [2] 58 d1 [2] 44 fe }

  condition:
    any of them
}