rule TTP_XOR_QUAD_CurrentVersionRun_2fa6 {
  strings:
    $key_2fa6 = { 7c c9 [2] 58 c7 [2] 73 eb [2] 5d c9 [2] 49 d2 [2] 46 c8 [2] 58 d5 [2] 5a d4 [2] 41 d2 [2] 5d d5 [2] 41 fa }

  condition:
    any of them
}