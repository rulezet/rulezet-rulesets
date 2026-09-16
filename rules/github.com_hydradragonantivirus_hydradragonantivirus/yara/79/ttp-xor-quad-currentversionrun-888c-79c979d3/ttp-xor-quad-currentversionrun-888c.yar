rule TTP_XOR_QUAD_CurrentVersionRun_888c {
  strings:
    $key_888c = { db e3 [2] ff ed [2] d4 c1 [2] fa e3 [2] ee f8 [2] e1 e2 [2] ff ff [2] fd fe [2] e6 f8 [2] fa ff [2] e6 d0 }

  condition:
    any of them
}