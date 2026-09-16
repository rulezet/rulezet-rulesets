rule TTP_XOR_QUAD_CurrentVersionRun_8d8d {
  strings:
    $key_8d8d = { de e2 [2] fa ec [2] d1 c0 [2] ff e2 [2] eb f9 [2] e4 e3 [2] fa fe [2] f8 ff [2] e3 f9 [2] ff fe [2] e3 d1 }

  condition:
    any of them
}