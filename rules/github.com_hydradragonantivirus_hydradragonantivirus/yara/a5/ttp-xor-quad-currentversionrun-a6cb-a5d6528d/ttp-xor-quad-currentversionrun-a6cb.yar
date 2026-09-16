rule TTP_XOR_QUAD_CurrentVersionRun_a6cb {
  strings:
    $key_a6cb = { f5 a4 [2] d1 aa [2] fa 86 [2] d4 a4 [2] c0 bf [2] cf a5 [2] d1 b8 [2] d3 b9 [2] c8 bf [2] d4 b8 [2] c8 97 }

  condition:
    any of them
}