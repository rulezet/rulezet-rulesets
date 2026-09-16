rule TTP_XOR_QUAD_CurrentVersionRun_a7d0 {
  strings:
    $key_a7d0 = { f4 bf [2] d0 b1 [2] fb 9d [2] d5 bf [2] c1 a4 [2] ce be [2] d0 a3 [2] d2 a2 [2] c9 a4 [2] d5 a3 [2] c9 8c }

  condition:
    any of them
}