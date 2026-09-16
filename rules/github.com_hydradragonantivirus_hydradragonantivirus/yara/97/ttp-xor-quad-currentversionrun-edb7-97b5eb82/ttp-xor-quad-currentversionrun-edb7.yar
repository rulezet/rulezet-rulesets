rule TTP_XOR_QUAD_CurrentVersionRun_edb7 {
  strings:
    $key_edb7 = { be d8 [2] 9a d6 [2] b1 fa [2] 9f d8 [2] 8b c3 [2] 84 d9 [2] 9a c4 [2] 98 c5 [2] 83 c3 [2] 9f c4 [2] 83 eb }

  condition:
    any of them
}