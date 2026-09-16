rule TTP_XOR_QUAD_CurrentVersionRun_e489 {
  strings:
    $key_e489 = { b7 e6 [2] 93 e8 [2] b8 c4 [2] 96 e6 [2] 82 fd [2] 8d e7 [2] 93 fa [2] 91 fb [2] 8a fd [2] 96 fa [2] 8a d5 }

  condition:
    any of them
}