rule TTP_XOR_QUAD_CurrentVersionRun_a6ac {
  strings:
    $key_a6ac = { f5 c3 [2] d1 cd [2] fa e1 [2] d4 c3 [2] c0 d8 [2] cf c2 [2] d1 df [2] d3 de [2] c8 d8 [2] d4 df [2] c8 f0 }

  condition:
    any of them
}