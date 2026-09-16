rule TTP_XOR_QUAD_CurrentVersionRun_88da {
  strings:
    $key_88da = { db b5 [2] ff bb [2] d4 97 [2] fa b5 [2] ee ae [2] e1 b4 [2] ff a9 [2] fd a8 [2] e6 ae [2] fa a9 [2] e6 86 }

  condition:
    any of them
}