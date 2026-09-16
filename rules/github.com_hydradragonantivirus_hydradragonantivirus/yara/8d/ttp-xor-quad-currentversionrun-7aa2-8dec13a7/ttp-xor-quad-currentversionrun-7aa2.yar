rule TTP_XOR_QUAD_CurrentVersionRun_7aa2 {
  strings:
    $key_7aa2 = { 29 cd [2] 0d c3 [2] 26 ef [2] 08 cd [2] 1c d6 [2] 13 cc [2] 0d d1 [2] 0f d0 [2] 14 d6 [2] 08 d1 [2] 14 fe }

  condition:
    any of them
}