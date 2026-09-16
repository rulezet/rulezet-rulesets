rule TTP_XOR_QUAD_CurrentVersionRun_c78e {
  strings:
    $key_c78e = { 94 e1 [2] b0 ef [2] 9b c3 [2] b5 e1 [2] a1 fa [2] ae e0 [2] b0 fd [2] b2 fc [2] a9 fa [2] b5 fd [2] a9 d2 }

  condition:
    any of them
}