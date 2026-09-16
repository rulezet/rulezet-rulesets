rule TTP_XOR_QUAD_CurrentVersionRun_64e7 {
  strings:
    $key_64e7 = { 37 88 [2] 13 86 [2] 38 aa [2] 16 88 [2] 02 93 [2] 0d 89 [2] 13 94 [2] 11 95 [2] 0a 93 [2] 16 94 [2] 0a bb }

  condition:
    any of them
}