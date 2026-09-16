rule TTP_XOR_QUAD_CurrentVersionRun_88c8 {
  strings:
    $key_88c8 = { db a7 [2] ff a9 [2] d4 85 [2] fa a7 [2] ee bc [2] e1 a6 [2] ff bb [2] fd ba [2] e6 bc [2] fa bb [2] e6 94 }

  condition:
    any of them
}