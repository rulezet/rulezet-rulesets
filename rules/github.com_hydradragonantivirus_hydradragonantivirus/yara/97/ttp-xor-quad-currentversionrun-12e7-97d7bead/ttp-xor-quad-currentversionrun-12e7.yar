rule TTP_XOR_QUAD_CurrentVersionRun_12e7 {
  strings:
    $key_12e7 = { 41 88 [2] 65 86 [2] 4e aa [2] 60 88 [2] 74 93 [2] 7b 89 [2] 65 94 [2] 67 95 [2] 7c 93 [2] 60 94 [2] 7c bb }

  condition:
    any of them
}