rule TTP_XOR_QUAD_CurrentVersionRun_b975 {
  strings:
    $key_b975 = { ea 1a [2] ce 14 [2] e5 38 [2] cb 1a [2] df 01 [2] d0 1b [2] ce 06 [2] cc 07 [2] d7 01 [2] cb 06 [2] d7 29 }

  condition:
    any of them
}