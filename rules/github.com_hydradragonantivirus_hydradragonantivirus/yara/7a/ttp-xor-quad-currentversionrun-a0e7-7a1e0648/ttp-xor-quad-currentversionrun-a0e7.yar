rule TTP_XOR_QUAD_CurrentVersionRun_a0e7 {
  strings:
    $key_a0e7 = { f3 88 [2] d7 86 [2] fc aa [2] d2 88 [2] c6 93 [2] c9 89 [2] d7 94 [2] d5 95 [2] ce 93 [2] d2 94 [2] ce bb }

  condition:
    any of them
}