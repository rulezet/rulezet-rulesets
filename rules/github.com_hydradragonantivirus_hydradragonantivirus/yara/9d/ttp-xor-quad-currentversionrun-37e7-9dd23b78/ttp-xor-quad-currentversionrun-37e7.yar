rule TTP_XOR_QUAD_CurrentVersionRun_37e7 {
  strings:
    $key_37e7 = { 64 88 [2] 40 86 [2] 6b aa [2] 45 88 [2] 51 93 [2] 5e 89 [2] 40 94 [2] 42 95 [2] 59 93 [2] 45 94 [2] 59 bb }

  condition:
    any of them
}