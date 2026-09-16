rule TTP_XOR_QUAD_CurrentVersionRun_6ce7 {
  strings:
    $key_6ce7 = { 3f 88 [2] 1b 86 [2] 30 aa [2] 1e 88 [2] 0a 93 [2] 05 89 [2] 1b 94 [2] 19 95 [2] 02 93 [2] 1e 94 [2] 02 bb }

  condition:
    any of them
}