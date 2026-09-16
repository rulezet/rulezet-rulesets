rule TTP_XOR_QUAD_CurrentVersionRun_88c6 {
  strings:
    $key_88c6 = { db a9 [2] ff a7 [2] d4 8b [2] fa a9 [2] ee b2 [2] e1 a8 [2] ff b5 [2] fd b4 [2] e6 b2 [2] fa b5 [2] e6 9a }

  condition:
    any of them
}