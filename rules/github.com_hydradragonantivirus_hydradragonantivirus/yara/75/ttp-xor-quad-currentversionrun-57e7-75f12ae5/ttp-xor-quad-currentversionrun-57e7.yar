rule TTP_XOR_QUAD_CurrentVersionRun_57e7 {
  strings:
    $key_57e7 = { 04 88 [2] 20 86 [2] 0b aa [2] 25 88 [2] 31 93 [2] 3e 89 [2] 20 94 [2] 22 95 [2] 39 93 [2] 25 94 [2] 39 bb }

  condition:
    any of them
}