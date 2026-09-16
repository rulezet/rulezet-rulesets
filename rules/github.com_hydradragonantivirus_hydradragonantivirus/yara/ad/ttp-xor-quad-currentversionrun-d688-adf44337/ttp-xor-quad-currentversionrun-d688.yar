rule TTP_XOR_QUAD_CurrentVersionRun_d688 {
  strings:
    $key_d688 = { 85 e7 [2] a1 e9 [2] 8a c5 [2] a4 e7 [2] b0 fc [2] bf e6 [2] a1 fb [2] a3 fa [2] b8 fc [2] a4 fb [2] b8 d4 }

  condition:
    any of them
}