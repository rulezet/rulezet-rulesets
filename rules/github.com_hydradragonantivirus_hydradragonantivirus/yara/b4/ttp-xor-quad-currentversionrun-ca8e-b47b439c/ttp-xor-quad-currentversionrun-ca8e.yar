rule TTP_XOR_QUAD_CurrentVersionRun_ca8e {
  strings:
    $key_ca8e = { 99 e1 [2] bd ef [2] 96 c3 [2] b8 e1 [2] ac fa [2] a3 e0 [2] bd fd [2] bf fc [2] a4 fa [2] b8 fd [2] a4 d2 }

  condition:
    any of them
}