rule TTP_XOR_QUAD_CurrentVersionRun_de8e {
  strings:
    $key_de8e = { 8d e1 [2] a9 ef [2] 82 c3 [2] ac e1 [2] b8 fa [2] b7 e0 [2] a9 fd [2] ab fc [2] b0 fa [2] ac fd [2] b0 d2 }

  condition:
    any of them
}