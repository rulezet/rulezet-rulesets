rule TTP_XOR_QUAD_CurrentVersionRun_23a6 {
  strings:
    $key_23a6 = { 70 c9 [2] 54 c7 [2] 7f eb [2] 51 c9 [2] 45 d2 [2] 4a c8 [2] 54 d5 [2] 56 d4 [2] 4d d2 [2] 51 d5 [2] 4d fa }

  condition:
    any of them
}