rule TTP_XOR_QUAD_CurrentVersionRun_c394 {
  strings:
    $key_c394 = { 90 fb [2] b4 f5 [2] 9f d9 [2] b1 fb [2] a5 e0 [2] aa fa [2] b4 e7 [2] b6 e6 [2] ad e0 [2] b1 e7 [2] ad c8 }

  condition:
    any of them
}