rule TTP_XOR_QUAD_CurrentVersionRun_88c1 {
  strings:
    $key_88c1 = { db ae [2] ff a0 [2] d4 8c [2] fa ae [2] ee b5 [2] e1 af [2] ff b2 [2] fd b3 [2] e6 b5 [2] fa b2 [2] e6 9d }

  condition:
    any of them
}