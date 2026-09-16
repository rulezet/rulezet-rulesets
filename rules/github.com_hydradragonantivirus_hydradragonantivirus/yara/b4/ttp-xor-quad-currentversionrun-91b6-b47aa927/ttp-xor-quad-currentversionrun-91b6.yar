rule TTP_XOR_QUAD_CurrentVersionRun_91b6 {
  strings:
    $key_91b6 = { c2 d9 [2] e6 d7 [2] cd fb [2] e3 d9 [2] f7 c2 [2] f8 d8 [2] e6 c5 [2] e4 c4 [2] ff c2 [2] e3 c5 [2] ff ea }

  condition:
    any of them
}