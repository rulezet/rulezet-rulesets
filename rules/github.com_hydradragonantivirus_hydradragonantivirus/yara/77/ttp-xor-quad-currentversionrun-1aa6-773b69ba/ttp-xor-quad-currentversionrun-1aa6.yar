rule TTP_XOR_QUAD_CurrentVersionRun_1aa6 {
  strings:
    $key_1aa6 = { 49 c9 [2] 6d c7 [2] 46 eb [2] 68 c9 [2] 7c d2 [2] 73 c8 [2] 6d d5 [2] 6f d4 [2] 74 d2 [2] 68 d5 [2] 74 fa }

  condition:
    any of them
}