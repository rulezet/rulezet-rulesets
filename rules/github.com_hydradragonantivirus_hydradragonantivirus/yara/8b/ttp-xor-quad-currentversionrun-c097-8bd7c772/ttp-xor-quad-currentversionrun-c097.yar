rule TTP_XOR_QUAD_CurrentVersionRun_c097 {
  strings:
    $key_c097 = { 93 f8 [2] b7 f6 [2] 9c da [2] b2 f8 [2] a6 e3 [2] a9 f9 [2] b7 e4 [2] b5 e5 [2] ae e3 [2] b2 e4 [2] ae cb }

  condition:
    any of them
}