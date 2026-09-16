rule TTP_XOR_QUAD_CurrentVersionRun_c18e {
  strings:
    $key_c18e = { 92 e1 [2] b6 ef [2] 9d c3 [2] b3 e1 [2] a7 fa [2] a8 e0 [2] b6 fd [2] b4 fc [2] af fa [2] b3 fd [2] af d2 }

  condition:
    any of them
}