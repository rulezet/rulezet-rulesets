rule TTP_XOR_QUAD_CurrentVersionRun_a6cd {
  strings:
    $key_a6cd = { f5 a2 [2] d1 ac [2] fa 80 [2] d4 a2 [2] c0 b9 [2] cf a3 [2] d1 be [2] d3 bf [2] c8 b9 [2] d4 be [2] c8 91 }

  condition:
    any of them
}