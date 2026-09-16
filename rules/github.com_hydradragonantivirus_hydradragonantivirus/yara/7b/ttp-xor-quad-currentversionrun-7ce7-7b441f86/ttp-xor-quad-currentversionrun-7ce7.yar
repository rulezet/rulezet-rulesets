rule TTP_XOR_QUAD_CurrentVersionRun_7ce7 {
  strings:
    $key_7ce7 = { 2f 88 [2] 0b 86 [2] 20 aa [2] 0e 88 [2] 1a 93 [2] 15 89 [2] 0b 94 [2] 09 95 [2] 12 93 [2] 0e 94 [2] 12 bb }

  condition:
    any of them
}