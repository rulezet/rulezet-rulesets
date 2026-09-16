rule TTP_XOR_QUAD_CurrentVersionRun_a09c {
  strings:
    $key_a09c = { f3 f3 [2] d7 fd [2] fc d1 [2] d2 f3 [2] c6 e8 [2] c9 f2 [2] d7 ef [2] d5 ee [2] ce e8 [2] d2 ef [2] ce c0 }

  condition:
    any of them
}