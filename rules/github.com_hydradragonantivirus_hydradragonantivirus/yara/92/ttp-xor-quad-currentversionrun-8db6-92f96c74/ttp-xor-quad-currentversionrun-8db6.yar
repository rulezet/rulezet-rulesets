rule TTP_XOR_QUAD_CurrentVersionRun_8db6 {
  strings:
    $key_8db6 = { de d9 [2] fa d7 [2] d1 fb [2] ff d9 [2] eb c2 [2] e4 d8 [2] fa c5 [2] f8 c4 [2] e3 c2 [2] ff c5 [2] e3 ea }

  condition:
    any of them
}