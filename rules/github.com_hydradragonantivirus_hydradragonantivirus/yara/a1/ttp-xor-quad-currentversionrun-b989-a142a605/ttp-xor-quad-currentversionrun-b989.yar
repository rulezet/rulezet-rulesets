rule TTP_XOR_QUAD_CurrentVersionRun_b989 {
  strings:
    $key_b989 = { ea e6 [2] ce e8 [2] e5 c4 [2] cb e6 [2] df fd [2] d0 e7 [2] ce fa [2] cc fb [2] d7 fd [2] cb fa [2] d7 d5 }

  condition:
    any of them
}