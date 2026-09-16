rule TTP_XOR_QUAD_CurrentVersionRun_c08e {
  strings:
    $key_c08e = { 93 e1 [2] b7 ef [2] 9c c3 [2] b2 e1 [2] a6 fa [2] a9 e0 [2] b7 fd [2] b5 fc [2] ae fa [2] b2 fd [2] ae d2 }

  condition:
    any of them
}