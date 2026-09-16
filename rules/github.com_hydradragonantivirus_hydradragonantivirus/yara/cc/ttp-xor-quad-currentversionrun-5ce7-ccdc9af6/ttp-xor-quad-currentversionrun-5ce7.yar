rule TTP_XOR_QUAD_CurrentVersionRun_5ce7 {
  strings:
    $key_5ce7 = { 0f 88 [2] 2b 86 [2] 00 aa [2] 2e 88 [2] 3a 93 [2] 35 89 [2] 2b 94 [2] 29 95 [2] 32 93 [2] 2e 94 [2] 32 bb }

  condition:
    any of them
}