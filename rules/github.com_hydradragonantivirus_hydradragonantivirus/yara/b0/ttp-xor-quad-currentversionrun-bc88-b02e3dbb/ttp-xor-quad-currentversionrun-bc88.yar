rule TTP_XOR_QUAD_CurrentVersionRun_bc88 {
  strings:
    $key_bc88 = { ef e7 [2] cb e9 [2] e0 c5 [2] ce e7 [2] da fc [2] d5 e6 [2] cb fb [2] c9 fa [2] d2 fc [2] ce fb [2] d2 d4 }

  condition:
    any of them
}