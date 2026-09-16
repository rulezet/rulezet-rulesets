rule TTP_XOR_QUAD_CurrentVersionRun_58e7 {
  strings:
    $key_58e7 = { 0b 88 [2] 2f 86 [2] 04 aa [2] 2a 88 [2] 3e 93 [2] 31 89 [2] 2f 94 [2] 2d 95 [2] 36 93 [2] 2a 94 [2] 36 bb }

  condition:
    any of them
}