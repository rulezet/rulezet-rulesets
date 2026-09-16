rule TTP_XOR_QUAD_CurrentVersionRun_a6bf {
  strings:
    $key_a6bf = { f5 d0 [2] d1 de [2] fa f2 [2] d4 d0 [2] c0 cb [2] cf d1 [2] d1 cc [2] d3 cd [2] c8 cb [2] d4 cc [2] c8 e3 }

  condition:
    any of them
}