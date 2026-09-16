rule TTP_XOR_QUAD_CurrentVersionRun_65e7 {
  strings:
    $key_65e7 = { 36 88 [2] 12 86 [2] 39 aa [2] 17 88 [2] 03 93 [2] 0c 89 [2] 12 94 [2] 10 95 [2] 0b 93 [2] 17 94 [2] 0b bb }

  condition:
    any of them
}