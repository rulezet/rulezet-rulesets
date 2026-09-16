rule TTP_XOR_QUAD_CurrentVersionRun_4ae7 {
  strings:
    $key_4ae7 = { 19 88 [2] 3d 86 [2] 16 aa [2] 38 88 [2] 2c 93 [2] 23 89 [2] 3d 94 [2] 3f 95 [2] 24 93 [2] 38 94 [2] 24 bb }

  condition:
    any of them
}