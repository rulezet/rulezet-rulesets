rule TTP_XOR_QUAD_CurrentVersionRun_31e7 {
  strings:
    $key_31e7 = { 62 88 [2] 46 86 [2] 6d aa [2] 43 88 [2] 57 93 [2] 58 89 [2] 46 94 [2] 44 95 [2] 5f 93 [2] 43 94 [2] 5f bb }

  condition:
    any of them
}