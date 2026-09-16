rule TTP_XOR_QUAD_CurrentVersionRun_6ae7 {
  strings:
    $key_6ae7 = { 39 88 [2] 1d 86 [2] 36 aa [2] 18 88 [2] 0c 93 [2] 03 89 [2] 1d 94 [2] 1f 95 [2] 04 93 [2] 18 94 [2] 04 bb }

  condition:
    any of them
}