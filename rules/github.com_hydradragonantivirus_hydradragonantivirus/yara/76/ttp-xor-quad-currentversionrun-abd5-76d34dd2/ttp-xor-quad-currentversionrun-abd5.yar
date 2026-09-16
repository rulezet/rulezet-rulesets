rule TTP_XOR_QUAD_CurrentVersionRun_abd5 {
  strings:
    $key_abd5 = { f8 ba [2] dc b4 [2] f7 98 [2] d9 ba [2] cd a1 [2] c2 bb [2] dc a6 [2] de a7 [2] c5 a1 [2] d9 a6 [2] c5 89 }

  condition:
    any of them
}