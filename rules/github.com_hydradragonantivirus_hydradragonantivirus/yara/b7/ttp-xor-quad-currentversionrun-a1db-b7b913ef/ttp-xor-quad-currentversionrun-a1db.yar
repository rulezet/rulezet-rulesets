rule TTP_XOR_QUAD_CurrentVersionRun_a1db {
  strings:
    $key_a1db = { f2 b4 [2] d6 ba [2] fd 96 [2] d3 b4 [2] c7 af [2] c8 b5 [2] d6 a8 [2] d4 a9 [2] cf af [2] d3 a8 [2] cf 87 }

  condition:
    any of them
}