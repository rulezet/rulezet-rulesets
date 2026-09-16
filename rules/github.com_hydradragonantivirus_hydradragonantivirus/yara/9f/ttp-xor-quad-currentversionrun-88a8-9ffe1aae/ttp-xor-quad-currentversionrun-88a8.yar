rule TTP_XOR_QUAD_CurrentVersionRun_88a8 {
  strings:
    $key_88a8 = { db c7 [2] ff c9 [2] d4 e5 [2] fa c7 [2] ee dc [2] e1 c6 [2] ff db [2] fd da [2] e6 dc [2] fa db [2] e6 f4 }

  condition:
    any of them
}