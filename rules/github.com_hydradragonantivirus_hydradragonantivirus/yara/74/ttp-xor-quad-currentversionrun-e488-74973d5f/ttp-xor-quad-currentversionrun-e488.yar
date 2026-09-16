rule TTP_XOR_QUAD_CurrentVersionRun_e488 {
  strings:
    $key_e488 = { b7 e7 [2] 93 e9 [2] b8 c5 [2] 96 e7 [2] 82 fc [2] 8d e6 [2] 93 fb [2] 91 fa [2] 8a fc [2] 96 fb [2] 8a d4 }

  condition:
    any of them
}