rule TTP_XOR_QUAD_CurrentVersionRun_88b9 {
  strings:
    $key_88b9 = { db d6 [2] ff d8 [2] d4 f4 [2] fa d6 [2] ee cd [2] e1 d7 [2] ff ca [2] fd cb [2] e6 cd [2] fa ca [2] e6 e5 }

  condition:
    any of them
}