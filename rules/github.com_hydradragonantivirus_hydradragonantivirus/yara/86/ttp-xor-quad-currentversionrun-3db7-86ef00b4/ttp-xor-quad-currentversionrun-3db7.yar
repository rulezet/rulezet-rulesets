rule TTP_XOR_QUAD_CurrentVersionRun_3db7 {
  strings:
    $key_3db7 = { 6e d8 [2] 4a d6 [2] 61 fa [2] 4f d8 [2] 5b c3 [2] 54 d9 [2] 4a c4 [2] 48 c5 [2] 53 c3 [2] 4f c4 [2] 53 eb }

  condition:
    any of them
}