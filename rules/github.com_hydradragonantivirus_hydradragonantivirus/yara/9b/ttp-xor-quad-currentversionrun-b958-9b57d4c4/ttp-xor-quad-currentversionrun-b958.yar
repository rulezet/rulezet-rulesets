rule TTP_XOR_QUAD_CurrentVersionRun_b958 {
  strings:
    $key_b958 = { ea 37 [2] ce 39 [2] e5 15 [2] cb 37 [2] df 2c [2] d0 36 [2] ce 2b [2] cc 2a [2] d7 2c [2] cb 2b [2] d7 04 }

  condition:
    any of them
}