rule TTP_XOR_QUAD_CurrentVersionRun_88ad {
  strings:
    $key_88ad = { db c2 [2] ff cc [2] d4 e0 [2] fa c2 [2] ee d9 [2] e1 c3 [2] ff de [2] fd df [2] e6 d9 [2] fa de [2] e6 f1 }

  condition:
    any of them
}