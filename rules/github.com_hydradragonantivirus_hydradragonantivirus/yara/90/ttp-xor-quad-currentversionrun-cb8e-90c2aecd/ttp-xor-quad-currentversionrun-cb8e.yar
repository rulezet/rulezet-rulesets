rule TTP_XOR_QUAD_CurrentVersionRun_cb8e {
  strings:
    $key_cb8e = { 98 e1 [2] bc ef [2] 97 c3 [2] b9 e1 [2] ad fa [2] a2 e0 [2] bc fd [2] be fc [2] a5 fa [2] b9 fd [2] a5 d2 }

  condition:
    any of them
}