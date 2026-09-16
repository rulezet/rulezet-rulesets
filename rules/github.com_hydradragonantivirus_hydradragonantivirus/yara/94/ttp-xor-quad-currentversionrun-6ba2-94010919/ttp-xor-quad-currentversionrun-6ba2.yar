rule TTP_XOR_QUAD_CurrentVersionRun_6ba2 {
  strings:
    $key_6ba2 = { 38 cd [2] 1c c3 [2] 37 ef [2] 19 cd [2] 0d d6 [2] 02 cc [2] 1c d1 [2] 1e d0 [2] 05 d6 [2] 19 d1 [2] 05 fe }

  condition:
    any of them
}