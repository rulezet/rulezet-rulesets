rule TTP_XOR_QUAD_CurrentVersionRun_a1bf {
  strings:
    $key_a1bf = { f2 d0 [2] d6 de [2] fd f2 [2] d3 d0 [2] c7 cb [2] c8 d1 [2] d6 cc [2] d4 cd [2] cf cb [2] d3 cc [2] cf e3 }

  condition:
    any of them
}