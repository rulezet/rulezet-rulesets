rule TTP_XOR_QUAD_CurrentVersionRun_8d8c {
  strings:
    $key_8d8c = { de e3 [2] fa ed [2] d1 c1 [2] ff e3 [2] eb f8 [2] e4 e2 [2] fa ff [2] f8 fe [2] e3 f8 [2] ff ff [2] e3 d0 }

  condition:
    any of them
}