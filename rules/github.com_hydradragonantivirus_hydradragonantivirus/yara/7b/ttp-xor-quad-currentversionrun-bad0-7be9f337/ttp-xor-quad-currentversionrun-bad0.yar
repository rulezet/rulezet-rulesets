rule TTP_XOR_QUAD_CurrentVersionRun_bad0 {
  strings:
    $key_bad0 = { e9 bf [2] cd b1 [2] e6 9d [2] c8 bf [2] dc a4 [2] d3 be [2] cd a3 [2] cf a2 [2] d4 a4 [2] c8 a3 [2] d4 8c }

  condition:
    any of them
}