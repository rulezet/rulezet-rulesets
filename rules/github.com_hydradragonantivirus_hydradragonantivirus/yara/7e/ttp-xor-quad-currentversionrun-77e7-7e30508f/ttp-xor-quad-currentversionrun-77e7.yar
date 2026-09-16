rule TTP_XOR_QUAD_CurrentVersionRun_77e7 {
  strings:
    $key_77e7 = { 24 88 [2] 00 86 [2] 2b aa [2] 05 88 [2] 11 93 [2] 1e 89 [2] 00 94 [2] 02 95 [2] 19 93 [2] 05 94 [2] 19 bb }

  condition:
    any of them
}