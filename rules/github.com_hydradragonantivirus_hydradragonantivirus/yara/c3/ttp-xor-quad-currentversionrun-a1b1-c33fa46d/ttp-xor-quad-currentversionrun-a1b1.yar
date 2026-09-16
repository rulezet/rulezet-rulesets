rule TTP_XOR_QUAD_CurrentVersionRun_a1b1 {
  strings:
    $key_a1b1 = { f2 de [2] d6 d0 [2] fd fc [2] d3 de [2] c7 c5 [2] c8 df [2] d6 c2 [2] d4 c3 [2] cf c5 [2] d3 c2 [2] cf ed }

  condition:
    any of them
}