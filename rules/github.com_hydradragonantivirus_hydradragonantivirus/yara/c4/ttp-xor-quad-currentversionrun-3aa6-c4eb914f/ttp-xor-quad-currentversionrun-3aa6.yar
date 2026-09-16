rule TTP_XOR_QUAD_CurrentVersionRun_3aa6 {
  strings:
    $key_3aa6 = { 69 c9 [2] 4d c7 [2] 66 eb [2] 48 c9 [2] 5c d2 [2] 53 c8 [2] 4d d5 [2] 4f d4 [2] 54 d2 [2] 48 d5 [2] 54 fa }

  condition:
    any of them
}