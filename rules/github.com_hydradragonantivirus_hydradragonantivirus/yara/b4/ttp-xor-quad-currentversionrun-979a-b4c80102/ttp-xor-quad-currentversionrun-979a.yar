rule TTP_XOR_QUAD_CurrentVersionRun_979a {
  strings:
    $key_979a = { c4 f5 [2] e0 fb [2] cb d7 [2] e5 f5 [2] f1 ee [2] fe f4 [2] e0 e9 [2] e2 e8 [2] f9 ee [2] e5 e9 [2] f9 c6 }

  condition:
    any of them
}