rule TTP_XOR_QUAD_CurrentVersionRun_0ae7 {
  strings:
    $key_0ae7 = { 59 88 [2] 7d 86 [2] 56 aa [2] 78 88 [2] 6c 93 [2] 63 89 [2] 7d 94 [2] 7f 95 [2] 64 93 [2] 78 94 [2] 64 bb }

  condition:
    any of them
}