rule TTP_XOR_QUAD_CurrentVersionRun_5ae7 {
  strings:
    $key_5ae7 = { 09 88 [2] 2d 86 [2] 06 aa [2] 28 88 [2] 3c 93 [2] 33 89 [2] 2d 94 [2] 2f 95 [2] 34 93 [2] 28 94 [2] 34 bb }

  condition:
    any of them
}