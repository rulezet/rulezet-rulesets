rule TTP_XOR_QUAD_CurrentVersionRun_33e7 {
  strings:
    $key_33e7 = { 60 88 [2] 44 86 [2] 6f aa [2] 41 88 [2] 55 93 [2] 5a 89 [2] 44 94 [2] 46 95 [2] 5d 93 [2] 41 94 [2] 5d bb }

  condition:
    any of them
}