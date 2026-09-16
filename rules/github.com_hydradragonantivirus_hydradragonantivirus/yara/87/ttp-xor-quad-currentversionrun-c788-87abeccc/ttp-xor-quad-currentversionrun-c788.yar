rule TTP_XOR_QUAD_CurrentVersionRun_c788 {
  strings:
    $key_c788 = { 94 e7 [2] b0 e9 [2] 9b c5 [2] b5 e7 [2] a1 fc [2] ae e6 [2] b0 fb [2] b2 fa [2] a9 fc [2] b5 fb [2] a9 d4 }

  condition:
    any of them
}