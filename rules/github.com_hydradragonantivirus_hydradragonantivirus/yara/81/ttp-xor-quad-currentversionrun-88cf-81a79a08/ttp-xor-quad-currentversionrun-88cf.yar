rule TTP_XOR_QUAD_CurrentVersionRun_88cf {
  strings:
    $key_88cf = { db a0 [2] ff ae [2] d4 82 [2] fa a0 [2] ee bb [2] e1 a1 [2] ff bc [2] fd bd [2] e6 bb [2] fa bc [2] e6 93 }

  condition:
    any of them
}