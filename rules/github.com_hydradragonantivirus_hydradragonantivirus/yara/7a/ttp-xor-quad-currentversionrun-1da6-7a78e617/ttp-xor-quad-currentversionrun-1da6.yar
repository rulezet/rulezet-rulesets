rule TTP_XOR_QUAD_CurrentVersionRun_1da6 {
  strings:
    $key_1da6 = { 4e c9 [2] 6a c7 [2] 41 eb [2] 6f c9 [2] 7b d2 [2] 74 c8 [2] 6a d5 [2] 68 d4 [2] 73 d2 [2] 6f d5 [2] 73 fa }

  condition:
    any of them
}