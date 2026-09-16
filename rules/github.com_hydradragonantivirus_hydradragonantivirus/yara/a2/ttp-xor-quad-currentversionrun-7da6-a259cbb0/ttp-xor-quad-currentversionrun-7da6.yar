rule TTP_XOR_QUAD_CurrentVersionRun_7da6 {
  strings:
    $key_7da6 = { 2e c9 [2] 0a c7 [2] 21 eb [2] 0f c9 [2] 1b d2 [2] 14 c8 [2] 0a d5 [2] 08 d4 [2] 13 d2 [2] 0f d5 [2] 13 fa }

  condition:
    any of them
}