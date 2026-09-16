rule TTP_XOR_QUAD_CurrentVersionRun_88a5 {
  strings:
    $key_88a5 = { db ca [2] ff c4 [2] d4 e8 [2] fa ca [2] ee d1 [2] e1 cb [2] ff d6 [2] fd d7 [2] e6 d1 [2] fa d6 [2] e6 f9 }

  condition:
    any of them
}