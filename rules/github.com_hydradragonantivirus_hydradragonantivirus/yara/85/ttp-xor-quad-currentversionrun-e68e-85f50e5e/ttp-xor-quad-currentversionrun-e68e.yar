rule TTP_XOR_QUAD_CurrentVersionRun_e68e {
  strings:
    $key_e68e = { b5 e1 [2] 91 ef [2] ba c3 [2] 94 e1 [2] 80 fa [2] 8f e0 [2] 91 fd [2] 93 fc [2] 88 fa [2] 94 fd [2] 88 d2 }

  condition:
    any of them
}