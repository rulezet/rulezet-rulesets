rule TTP_XOR_QUAD_CurrentVersionRun_938b {
  strings:
    $key_938b = { c0 e4 [2] e4 ea [2] cf c6 [2] e1 e4 [2] f5 ff [2] fa e5 [2] e4 f8 [2] e6 f9 [2] fd ff [2] e1 f8 [2] fd d7 }

  condition:
    any of them
}