rule TTP_XOR_QUAD_CurrentVersionRun_888a {
  strings:
    $key_888a = { db e5 [2] ff eb [2] d4 c7 [2] fa e5 [2] ee fe [2] e1 e4 [2] ff f9 [2] fd f8 [2] e6 fe [2] fa f9 [2] e6 d6 }

  condition:
    any of them
}