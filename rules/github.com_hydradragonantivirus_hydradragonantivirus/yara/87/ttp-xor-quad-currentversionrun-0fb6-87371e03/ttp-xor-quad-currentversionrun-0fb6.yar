rule TTP_XOR_QUAD_CurrentVersionRun_0fb6 {
  strings:
    $key_0fb6 = { 5c d9 [2] 78 d7 [2] 53 fb [2] 7d d9 [2] 69 c2 [2] 66 d8 [2] 78 c5 [2] 7a c4 [2] 61 c2 [2] 7d c5 [2] 61 ea }

  condition:
    any of them
}