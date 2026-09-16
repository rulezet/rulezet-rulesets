rule TTP_XOR_QUAD_CurrentVersionRun_a0dd {
  strings:
    $key_a0dd = { f3 b2 [2] d7 bc [2] fc 90 [2] d2 b2 [2] c6 a9 [2] c9 b3 [2] d7 ae [2] d5 af [2] ce a9 [2] d2 ae [2] ce 81 }

  condition:
    any of them
}