rule TTP_XOR_QUAD_CurrentVersionRun_bce7 {
  strings:
    $key_bce7 = { ef 88 [2] cb 86 [2] e0 aa [2] ce 88 [2] da 93 [2] d5 89 [2] cb 94 [2] c9 95 [2] d2 93 [2] ce 94 [2] d2 bb }

  condition:
    any of them
}