rule TTP_XOR_QUAD_CurrentVersionRun_aaa6 {
  strings:
    $key_aaa6 = { f9 c9 [2] dd c7 [2] f6 eb [2] d8 c9 [2] cc d2 [2] c3 c8 [2] dd d5 [2] df d4 [2] c4 d2 [2] d8 d5 [2] c4 fa }

  condition:
    any of them
}