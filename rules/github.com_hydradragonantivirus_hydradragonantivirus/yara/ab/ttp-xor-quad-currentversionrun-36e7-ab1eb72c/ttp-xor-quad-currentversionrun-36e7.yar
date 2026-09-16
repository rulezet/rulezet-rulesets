rule TTP_XOR_QUAD_CurrentVersionRun_36e7 {
  strings:
    $key_36e7 = { 65 88 [2] 41 86 [2] 6a aa [2] 44 88 [2] 50 93 [2] 5f 89 [2] 41 94 [2] 43 95 [2] 58 93 [2] 44 94 [2] 58 bb }

  condition:
    any of them
}