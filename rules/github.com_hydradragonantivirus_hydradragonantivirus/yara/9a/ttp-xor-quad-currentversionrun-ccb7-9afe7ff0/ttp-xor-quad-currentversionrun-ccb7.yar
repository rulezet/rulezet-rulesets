rule TTP_XOR_QUAD_CurrentVersionRun_ccb7 {
  strings:
    $key_ccb7 = { 9f d8 [2] bb d6 [2] 90 fa [2] be d8 [2] aa c3 [2] a5 d9 [2] bb c4 [2] b9 c5 [2] a2 c3 [2] be c4 [2] a2 eb }

  condition:
    any of them
}