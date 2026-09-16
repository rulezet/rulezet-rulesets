rule TTP_XOR_QUAD_CurrentVersionRun_5fe7 {
  strings:
    $key_5fe7 = { 0c 88 [2] 28 86 [2] 03 aa [2] 2d 88 [2] 39 93 [2] 36 89 [2] 28 94 [2] 2a 95 [2] 31 93 [2] 2d 94 [2] 31 bb }

  condition:
    any of them
}