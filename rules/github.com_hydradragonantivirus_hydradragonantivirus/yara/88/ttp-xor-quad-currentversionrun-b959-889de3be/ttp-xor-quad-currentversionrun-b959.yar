rule TTP_XOR_QUAD_CurrentVersionRun_b959 {
  strings:
    $key_b959 = { ea 36 [2] ce 38 [2] e5 14 [2] cb 36 [2] df 2d [2] d0 37 [2] ce 2a [2] cc 2b [2] d7 2d [2] cb 2a [2] d7 05 }

  condition:
    any of them
}