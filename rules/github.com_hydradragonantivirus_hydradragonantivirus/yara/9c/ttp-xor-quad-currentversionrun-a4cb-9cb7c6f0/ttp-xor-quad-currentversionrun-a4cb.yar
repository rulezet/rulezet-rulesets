rule TTP_XOR_QUAD_CurrentVersionRun_a4cb {
  strings:
    $key_a4cb = { f7 a4 [2] d3 aa [2] f8 86 [2] d6 a4 [2] c2 bf [2] cd a5 [2] d3 b8 [2] d1 b9 [2] ca bf [2] d6 b8 [2] ca 97 }

  condition:
    any of them
}