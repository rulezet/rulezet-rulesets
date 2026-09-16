rule TTP_XOR_QUAD_CurrentVersionRun_2ce7 {
  strings:
    $key_2ce7 = { 7f 88 [2] 5b 86 [2] 70 aa [2] 5e 88 [2] 4a 93 [2] 45 89 [2] 5b 94 [2] 59 95 [2] 42 93 [2] 5e 94 [2] 42 bb }

  condition:
    any of them
}