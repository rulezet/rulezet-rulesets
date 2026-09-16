rule TTP_XOR_QUAD_CurrentVersionRun_14e7 {
  strings:
    $key_14e7 = { 47 88 [2] 63 86 [2] 48 aa [2] 66 88 [2] 72 93 [2] 7d 89 [2] 63 94 [2] 61 95 [2] 7a 93 [2] 66 94 [2] 7a bb }

  condition:
    any of them
}