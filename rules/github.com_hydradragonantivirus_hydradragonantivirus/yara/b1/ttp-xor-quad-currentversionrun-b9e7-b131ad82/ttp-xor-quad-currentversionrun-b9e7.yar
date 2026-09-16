rule TTP_XOR_QUAD_CurrentVersionRun_b9e7 {
  strings:
    $key_b9e7 = { ea 88 [2] ce 86 [2] e5 aa [2] cb 88 [2] df 93 [2] d0 89 [2] ce 94 [2] cc 95 [2] d7 93 [2] cb 94 [2] d7 bb }

  condition:
    any of them
}