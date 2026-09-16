rule TTP_XOR_QUAD_CurrentVersionRun_78e7 {
  strings:
    $key_78e7 = { 2b 88 [2] 0f 86 [2] 24 aa [2] 0a 88 [2] 1e 93 [2] 11 89 [2] 0f 94 [2] 0d 95 [2] 16 93 [2] 0a 94 [2] 16 bb }

  condition:
    any of them
}