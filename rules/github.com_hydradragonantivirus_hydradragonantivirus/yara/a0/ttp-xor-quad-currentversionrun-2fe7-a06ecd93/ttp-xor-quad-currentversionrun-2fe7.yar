rule TTP_XOR_QUAD_CurrentVersionRun_2fe7 {
  strings:
    $key_2fe7 = { 7c 88 [2] 58 86 [2] 73 aa [2] 5d 88 [2] 49 93 [2] 46 89 [2] 58 94 [2] 5a 95 [2] 41 93 [2] 5d 94 [2] 41 bb }

  condition:
    any of them
}