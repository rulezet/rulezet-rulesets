rule TTP_XOR_QUAD_CurrentVersionRun_d795 {
  strings:
    $key_d795 = { 84 fa [2] a0 f4 [2] 8b d8 [2] a5 fa [2] b1 e1 [2] be fb [2] a0 e6 [2] a2 e7 [2] b9 e1 [2] a5 e6 [2] b9 c9 }

  condition:
    any of them
}