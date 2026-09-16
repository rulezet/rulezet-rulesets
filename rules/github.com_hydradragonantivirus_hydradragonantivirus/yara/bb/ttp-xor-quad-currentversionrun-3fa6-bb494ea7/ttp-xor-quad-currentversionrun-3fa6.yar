rule TTP_XOR_QUAD_CurrentVersionRun_3fa6 {
  strings:
    $key_3fa6 = { 6c c9 [2] 48 c7 [2] 63 eb [2] 4d c9 [2] 59 d2 [2] 56 c8 [2] 48 d5 [2] 4a d4 [2] 51 d2 [2] 4d d5 [2] 51 fa }

  condition:
    any of them
}