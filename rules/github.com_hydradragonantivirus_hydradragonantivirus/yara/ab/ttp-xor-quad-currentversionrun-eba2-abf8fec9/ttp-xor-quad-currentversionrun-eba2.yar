rule TTP_XOR_QUAD_CurrentVersionRun_eba2 {
  strings:
    $key_eba2 = { b8 cd [2] 9c c3 [2] b7 ef [2] 99 cd [2] 8d d6 [2] 82 cc [2] 9c d1 [2] 9e d0 [2] 85 d6 [2] 99 d1 [2] 85 fe }

  condition:
    any of them
}