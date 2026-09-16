rule TTP_XOR_QUAD_CurrentVersionRun_0fa6 {
  strings:
    $key_0fa6 = { 5c c9 [2] 78 c7 [2] 53 eb [2] 7d c9 [2] 69 d2 [2] 66 c8 [2] 78 d5 [2] 7a d4 [2] 61 d2 [2] 7d d5 [2] 61 fa }

  condition:
    any of them
}