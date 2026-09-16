rule TTP_XOR_QUAD_CurrentVersionRun_88d4 {
  strings:
    $key_88d4 = { db bb [2] ff b5 [2] d4 99 [2] fa bb [2] ee a0 [2] e1 ba [2] ff a7 [2] fd a6 [2] e6 a0 [2] fa a7 [2] e6 88 }

  condition:
    any of them
}