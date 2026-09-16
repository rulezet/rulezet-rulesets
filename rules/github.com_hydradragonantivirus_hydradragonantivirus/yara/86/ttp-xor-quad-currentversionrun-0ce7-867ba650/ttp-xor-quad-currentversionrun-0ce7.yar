rule TTP_XOR_QUAD_CurrentVersionRun_0ce7 {
  strings:
    $key_0ce7 = { 5f 88 [2] 7b 86 [2] 50 aa [2] 7e 88 [2] 6a 93 [2] 65 89 [2] 7b 94 [2] 79 95 [2] 62 93 [2] 7e 94 [2] 62 bb }

  condition:
    any of them
}