rule TTP_XOR_QUAD_CurrentVersionRun_a79d {
  strings:
    $key_a79d = { f4 f2 [2] d0 fc [2] fb d0 [2] d5 f2 [2] c1 e9 [2] ce f3 [2] d0 ee [2] d2 ef [2] c9 e9 [2] d5 ee [2] c9 c1 }

  condition:
    any of them
}