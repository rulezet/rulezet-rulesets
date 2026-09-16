rule TTP_XOR_QUAD_CurrentVersionRun_eab7 {
  strings:
    $key_eab7 = { b9 d8 [2] 9d d6 [2] b6 fa [2] 98 d8 [2] 8c c3 [2] 83 d9 [2] 9d c4 [2] 9f c5 [2] 84 c3 [2] 98 c4 [2] 84 eb }

  condition:
    any of them
}