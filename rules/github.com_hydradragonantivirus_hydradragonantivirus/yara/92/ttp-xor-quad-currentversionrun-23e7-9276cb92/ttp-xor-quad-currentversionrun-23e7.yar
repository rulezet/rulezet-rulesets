rule TTP_XOR_QUAD_CurrentVersionRun_23e7 {
  strings:
    $key_23e7 = { 70 88 [2] 54 86 [2] 7f aa [2] 51 88 [2] 45 93 [2] 4a 89 [2] 54 94 [2] 56 95 [2] 4d 93 [2] 51 94 [2] 4d bb }

  condition:
    any of them
}