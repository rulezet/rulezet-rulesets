rule TTP_XOR_QUAD_CurrentVersionRun_88cb {
  strings:
    $key_88cb = { db a4 [2] ff aa [2] d4 86 [2] fa a4 [2] ee bf [2] e1 a5 [2] ff b8 [2] fd b9 [2] e6 bf [2] fa b8 [2] e6 97 }

  condition:
    any of them
}