rule TTP_XOR_QUAD_CurrentVersionRun_a4f2 {
  strings:
    $key_a4f2 = { f7 9d [2] d3 93 [2] f8 bf [2] d6 9d [2] c2 86 [2] cd 9c [2] d3 81 [2] d1 80 [2] ca 86 [2] d6 81 [2] ca ae }

  condition:
    any of them
}