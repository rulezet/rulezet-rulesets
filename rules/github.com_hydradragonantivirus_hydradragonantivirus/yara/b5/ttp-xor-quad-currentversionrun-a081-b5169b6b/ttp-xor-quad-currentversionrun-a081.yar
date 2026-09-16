rule TTP_XOR_QUAD_CurrentVersionRun_a081 {
  strings:
    $key_a081 = { f3 ee [2] d7 e0 [2] fc cc [2] d2 ee [2] c6 f5 [2] c9 ef [2] d7 f2 [2] d5 f3 [2] ce f5 [2] d2 f2 [2] ce dd }

  condition:
    any of them
}