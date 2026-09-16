rule TTP_XOR_QUAD_CurrentVersionRun_a7b3 {
  strings:
    $key_a7b3 = { f4 dc [2] d0 d2 [2] fb fe [2] d5 dc [2] c1 c7 [2] ce dd [2] d0 c0 [2] d2 c1 [2] c9 c7 [2] d5 c0 [2] c9 ef }

  condition:
    any of them
}