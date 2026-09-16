rule TTP_XOR_QUAD_CurrentVersionRun_ce8e {
  strings:
    $key_ce8e = { 9d e1 [2] b9 ef [2] 92 c3 [2] bc e1 [2] a8 fa [2] a7 e0 [2] b9 fd [2] bb fc [2] a0 fa [2] bc fd [2] a0 d2 }

  condition:
    any of them
}