rule TTP_XOR_QUAD_CurrentVersionRun_09e7 {
  strings:
    $key_09e7 = { 5a 88 [2] 7e 86 [2] 55 aa [2] 7b 88 [2] 6f 93 [2] 60 89 [2] 7e 94 [2] 7c 95 [2] 67 93 [2] 7b 94 [2] 67 bb }

  condition:
    any of them
}