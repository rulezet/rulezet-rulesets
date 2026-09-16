rule TTP_XOR_QUAD_CurrentVersionRun_0aa6 {
  strings:
    $key_0aa6 = { 59 c9 [2] 7d c7 [2] 56 eb [2] 78 c9 [2] 6c d2 [2] 63 c8 [2] 7d d5 [2] 7f d4 [2] 64 d2 [2] 78 d5 [2] 64 fa }

  condition:
    any of them
}