rule TTP_XOR_QUAD_CurrentVersionRun_909a {
  strings:
    $key_909a = { c3 f5 [2] e7 fb [2] cc d7 [2] e2 f5 [2] f6 ee [2] f9 f4 [2] e7 e9 [2] e5 e8 [2] fe ee [2] e2 e9 [2] fe c6 }

  condition:
    any of them
}