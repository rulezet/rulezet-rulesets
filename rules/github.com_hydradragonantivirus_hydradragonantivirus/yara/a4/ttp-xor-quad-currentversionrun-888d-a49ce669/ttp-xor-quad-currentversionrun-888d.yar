rule TTP_XOR_QUAD_CurrentVersionRun_888d {
  strings:
    $key_888d = { db e2 [2] ff ec [2] d4 c0 [2] fa e2 [2] ee f9 [2] e1 e3 [2] ff fe [2] fd ff [2] e6 f9 [2] fa fe [2] e6 d1 }

  condition:
    any of them
}