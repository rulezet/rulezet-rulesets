rule TTP_XOR_QUAD_CurrentVersionRun_bb9a {
  strings:
    $key_bb9a = { e8 f5 [2] cc fb [2] e7 d7 [2] c9 f5 [2] dd ee [2] d2 f4 [2] cc e9 [2] ce e8 [2] d5 ee [2] c9 e9 [2] d5 c6 }

  condition:
    any of them
}