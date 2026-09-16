rule TTP_XOR_QUAD_CurrentVersionRun_a79a {
  strings:
    $key_a79a = { f4 f5 [2] d0 fb [2] fb d7 [2] d5 f5 [2] c1 ee [2] ce f4 [2] d0 e9 [2] d2 e8 [2] c9 ee [2] d5 e9 [2] c9 c6 }

  condition:
    any of them
}