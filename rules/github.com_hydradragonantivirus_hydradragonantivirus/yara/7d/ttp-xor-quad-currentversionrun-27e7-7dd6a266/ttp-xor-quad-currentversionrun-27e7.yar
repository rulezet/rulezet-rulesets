rule TTP_XOR_QUAD_CurrentVersionRun_27e7 {
  strings:
    $key_27e7 = { 74 88 [2] 50 86 [2] 7b aa [2] 55 88 [2] 41 93 [2] 4e 89 [2] 50 94 [2] 52 95 [2] 49 93 [2] 55 94 [2] 49 bb }

  condition:
    any of them
}