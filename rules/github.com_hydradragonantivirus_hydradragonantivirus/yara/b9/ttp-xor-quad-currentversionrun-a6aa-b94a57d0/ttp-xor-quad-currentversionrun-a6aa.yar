rule TTP_XOR_QUAD_CurrentVersionRun_a6aa {
  strings:
    $key_a6aa = { f5 c5 [2] d1 cb [2] fa e7 [2] d4 c5 [2] c0 de [2] cf c4 [2] d1 d9 [2] d3 d8 [2] c8 de [2] d4 d9 [2] c8 f6 }

  condition:
    any of them
}