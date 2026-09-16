rule TTP_XOR_QUAD_CurrentVersionRun_88db {
  strings:
    $key_88db = { db b4 [2] ff ba [2] d4 96 [2] fa b4 [2] ee af [2] e1 b5 [2] ff a8 [2] fd a9 [2] e6 af [2] fa a8 [2] e6 87 }

  condition:
    any of them
}