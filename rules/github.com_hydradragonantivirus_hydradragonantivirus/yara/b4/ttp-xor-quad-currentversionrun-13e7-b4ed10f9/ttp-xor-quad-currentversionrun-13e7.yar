rule TTP_XOR_QUAD_CurrentVersionRun_13e7 {
  strings:
    $key_13e7 = { 40 88 [2] 64 86 [2] 4f aa [2] 61 88 [2] 75 93 [2] 7a 89 [2] 64 94 [2] 66 95 [2] 7d 93 [2] 61 94 [2] 7d bb }

  condition:
    any of them
}