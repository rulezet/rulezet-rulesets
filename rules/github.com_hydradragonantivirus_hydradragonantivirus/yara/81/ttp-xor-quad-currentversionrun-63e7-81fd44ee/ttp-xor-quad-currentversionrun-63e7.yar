rule TTP_XOR_QUAD_CurrentVersionRun_63e7 {
  strings:
    $key_63e7 = { 30 88 [2] 14 86 [2] 3f aa [2] 11 88 [2] 05 93 [2] 0a 89 [2] 14 94 [2] 16 95 [2] 0d 93 [2] 11 94 [2] 0d bb }

  condition:
    any of them
}