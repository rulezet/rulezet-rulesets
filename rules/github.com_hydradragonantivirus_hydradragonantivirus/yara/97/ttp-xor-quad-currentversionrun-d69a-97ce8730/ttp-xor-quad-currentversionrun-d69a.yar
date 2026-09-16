rule TTP_XOR_QUAD_CurrentVersionRun_d69a {
  strings:
    $key_d69a = { 85 f5 [2] a1 fb [2] 8a d7 [2] a4 f5 [2] b0 ee [2] bf f4 [2] a1 e9 [2] a3 e8 [2] b8 ee [2] a4 e9 [2] b8 c6 }

  condition:
    any of them
}