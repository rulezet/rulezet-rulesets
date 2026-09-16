rule TTP_XOR_QUAD_CurrentVersionRun_bc95 {
  strings:
    $key_bc95 = { ef fa [2] cb f4 [2] e0 d8 [2] ce fa [2] da e1 [2] d5 fb [2] cb e6 [2] c9 e7 [2] d2 e1 [2] ce e6 [2] d2 c9 }

  condition:
    any of them
}