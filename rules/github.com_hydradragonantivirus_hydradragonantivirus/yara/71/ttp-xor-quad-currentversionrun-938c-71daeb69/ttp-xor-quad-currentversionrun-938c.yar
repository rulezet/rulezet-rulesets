rule TTP_XOR_QUAD_CurrentVersionRun_938c {
  strings:
    $key_938c = { c0 e3 [2] e4 ed [2] cf c1 [2] e1 e3 [2] f5 f8 [2] fa e2 [2] e4 ff [2] e6 fe [2] fd f8 [2] e1 ff [2] fd d0 }

  condition:
    any of them
}