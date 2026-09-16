rule TTP_XOR_QUAD_CurrentVersionRun_a6db {
  strings:
    $key_a6db = { f5 b4 [2] d1 ba [2] fa 96 [2] d4 b4 [2] c0 af [2] cf b5 [2] d1 a8 [2] d3 a9 [2] c8 af [2] d4 a8 [2] c8 87 }

  condition:
    any of them
}