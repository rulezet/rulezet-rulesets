rule TTP_XOR_QUAD_CurrentVersionRun_d194 {
  strings:
    $key_d194 = { 82 fb [2] a6 f5 [2] 8d d9 [2] a3 fb [2] b7 e0 [2] b8 fa [2] a6 e7 [2] a4 e6 [2] bf e0 [2] a3 e7 [2] bf c8 }

  condition:
    any of them
}