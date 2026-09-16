rule TTP_XOR_QUAD_CurrentVersionRun_f7e7 {
  strings:
    $key_f7e7 = { a4 88 [2] 80 86 [2] ab aa [2] 85 88 [2] 91 93 [2] 9e 89 [2] 80 94 [2] 82 95 [2] 99 93 [2] 85 94 [2] 99 bb }

  condition:
    any of them
}