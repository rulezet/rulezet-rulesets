rule TTP_XOR_QUAD_CurrentVersionRun_11e7 {
  strings:
    $key_11e7 = { 42 88 [2] 66 86 [2] 4d aa [2] 63 88 [2] 77 93 [2] 78 89 [2] 66 94 [2] 64 95 [2] 7f 93 [2] 63 94 [2] 7f bb }

  condition:
    any of them
}