rule TTP_XOR_QUAD_CurrentVersionRun_5de7 {
  strings:
    $key_5de7 = { 0e 88 [2] 2a 86 [2] 01 aa [2] 2f 88 [2] 3b 93 [2] 34 89 [2] 2a 94 [2] 28 95 [2] 33 93 [2] 2f 94 [2] 33 bb }

  condition:
    any of them
}