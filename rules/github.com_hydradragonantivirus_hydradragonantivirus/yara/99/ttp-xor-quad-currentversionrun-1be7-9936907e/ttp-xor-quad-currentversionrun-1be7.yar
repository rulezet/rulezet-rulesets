rule TTP_XOR_QUAD_CurrentVersionRun_1be7 {
  strings:
    $key_1be7 = { 48 88 [2] 6c 86 [2] 47 aa [2] 69 88 [2] 7d 93 [2] 72 89 [2] 6c 94 [2] 6e 95 [2] 75 93 [2] 69 94 [2] 75 bb }

  condition:
    any of them
}