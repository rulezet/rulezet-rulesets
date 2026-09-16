rule TTP_XOR_QUAD_CurrentVersionRun_1fe7 {
  strings:
    $key_1fe7 = { 4c 88 [2] 68 86 [2] 43 aa [2] 6d 88 [2] 79 93 [2] 76 89 [2] 68 94 [2] 6a 95 [2] 71 93 [2] 6d 94 [2] 71 bb }

  condition:
    any of them
}