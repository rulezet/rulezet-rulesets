rule TTP_XOR_QUAD_CurrentVersionRun_839a {
  strings:
    $key_839a = { d0 f5 [2] f4 fb [2] df d7 [2] f1 f5 [2] e5 ee [2] ea f4 [2] f4 e9 [2] f6 e8 [2] ed ee [2] f1 e9 [2] ed c6 }

  condition:
    any of them
}