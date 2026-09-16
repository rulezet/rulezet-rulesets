rule TTP_XOR_QUAD_CurrentVersionRun_c3b7 {
  strings:
    $key_c3b7 = { 90 d8 [2] b4 d6 [2] 9f fa [2] b1 d8 [2] a5 c3 [2] aa d9 [2] b4 c4 [2] b6 c5 [2] ad c3 [2] b1 c4 [2] ad eb }

  condition:
    any of them
}