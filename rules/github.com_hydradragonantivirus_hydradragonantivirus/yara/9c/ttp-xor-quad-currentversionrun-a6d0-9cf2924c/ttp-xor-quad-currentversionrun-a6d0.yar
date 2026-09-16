rule TTP_XOR_QUAD_CurrentVersionRun_a6d0 {
  strings:
    $key_a6d0 = { f5 bf [2] d1 b1 [2] fa 9d [2] d4 bf [2] c0 a4 [2] cf be [2] d1 a3 [2] d3 a2 [2] c8 a4 [2] d4 a3 [2] c8 8c }

  condition:
    any of them
}