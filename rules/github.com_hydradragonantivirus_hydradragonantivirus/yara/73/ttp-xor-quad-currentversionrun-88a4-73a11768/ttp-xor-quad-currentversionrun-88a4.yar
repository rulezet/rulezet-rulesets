rule TTP_XOR_QUAD_CurrentVersionRun_88a4 {
  strings:
    $key_88a4 = { db cb [2] ff c5 [2] d4 e9 [2] fa cb [2] ee d0 [2] e1 ca [2] ff d7 [2] fd d6 [2] e6 d0 [2] fa d7 [2] e6 f8 }

  condition:
    any of them
}