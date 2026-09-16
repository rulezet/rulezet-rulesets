rule TTP_XOR_QUAD_CurrentVersionRun_a4d0 {
  strings:
    $key_a4d0 = { f7 bf [2] d3 b1 [2] f8 9d [2] d6 bf [2] c2 a4 [2] cd be [2] d3 a3 [2] d1 a2 [2] ca a4 [2] d6 a3 [2] ca 8c }

  condition:
    any of them
}