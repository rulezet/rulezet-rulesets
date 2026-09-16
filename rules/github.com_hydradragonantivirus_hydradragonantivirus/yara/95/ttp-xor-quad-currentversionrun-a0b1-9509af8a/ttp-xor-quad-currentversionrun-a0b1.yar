rule TTP_XOR_QUAD_CurrentVersionRun_a0b1 {
  strings:
    $key_a0b1 = { f3 de [2] d7 d0 [2] fc fc [2] d2 de [2] c6 c5 [2] c9 df [2] d7 c2 [2] d5 c3 [2] ce c5 [2] d2 c2 [2] ce ed }

  condition:
    any of them
}