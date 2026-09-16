rule TTP_XOR_QUAD_CurrentVersionRun_b7e7 {
  strings:
    $key_b7e7 = { e4 88 [2] c0 86 [2] eb aa [2] c5 88 [2] d1 93 [2] de 89 [2] c0 94 [2] c2 95 [2] d9 93 [2] c5 94 [2] d9 bb }

  condition:
    any of them
}