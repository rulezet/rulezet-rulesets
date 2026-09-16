rule TTP_XOR_QUAD_CurrentVersionRun_6aa6 {
  strings:
    $key_6aa6 = { 39 c9 [2] 1d c7 [2] 36 eb [2] 18 c9 [2] 0c d2 [2] 03 c8 [2] 1d d5 [2] 1f d4 [2] 04 d2 [2] 18 d5 [2] 04 fa }

  condition:
    any of them
}