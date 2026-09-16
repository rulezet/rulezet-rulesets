rule TTP_XOR_QUAD_CurrentVersionRun_a0ad {
  strings:
    $key_a0ad = { f3 c2 [2] d7 cc [2] fc e0 [2] d2 c2 [2] c6 d9 [2] c9 c3 [2] d7 de [2] d5 df [2] ce d9 [2] d2 de [2] ce f1 }

  condition:
    any of them
}