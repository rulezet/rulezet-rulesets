rule TTP_XOR_QUAD_CurrentVersionRun_16e7 {
  strings:
    $key_16e7 = { 45 88 [2] 61 86 [2] 4a aa [2] 64 88 [2] 70 93 [2] 7f 89 [2] 61 94 [2] 63 95 [2] 78 93 [2] 64 94 [2] 78 bb }

  condition:
    any of them
}