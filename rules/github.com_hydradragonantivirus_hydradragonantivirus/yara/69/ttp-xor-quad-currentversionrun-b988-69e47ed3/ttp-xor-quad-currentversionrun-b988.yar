rule TTP_XOR_QUAD_CurrentVersionRun_b988 {
  strings:
    $key_b988 = { ea e7 [2] ce e9 [2] e5 c5 [2] cb e7 [2] df fc [2] d0 e6 [2] ce fb [2] cc fa [2] d7 fc [2] cb fb [2] d7 d4 }

  condition:
    any of them
}