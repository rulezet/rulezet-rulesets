rule TTP_XOR_QUAD_CurrentVersionRun_2de7 {
  strings:
    $key_2de7 = { 7e 88 [2] 5a 86 [2] 71 aa [2] 5f 88 [2] 4b 93 [2] 44 89 [2] 5a 94 [2] 58 95 [2] 43 93 [2] 5f 94 [2] 43 bb }

  condition:
    any of them
}