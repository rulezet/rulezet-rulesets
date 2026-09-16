rule TTP_XOR_QUAD_CurrentVersionRun_c489 {
  strings:
    $key_c489 = { 97 e6 [2] b3 e8 [2] 98 c4 [2] b6 e6 [2] a2 fd [2] ad e7 [2] b3 fa [2] b1 fb [2] aa fd [2] b6 fa [2] aa d5 }

  condition:
    any of them
}