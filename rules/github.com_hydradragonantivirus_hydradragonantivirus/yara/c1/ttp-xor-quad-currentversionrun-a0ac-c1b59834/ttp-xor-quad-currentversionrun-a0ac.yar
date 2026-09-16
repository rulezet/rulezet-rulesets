rule TTP_XOR_QUAD_CurrentVersionRun_a0ac {
  strings:
    $key_a0ac = { f3 c3 [2] d7 cd [2] fc e1 [2] d2 c3 [2] c6 d8 [2] c9 c2 [2] d7 df [2] d5 de [2] ce d8 [2] d2 df [2] ce f0 }

  condition:
    any of them
}