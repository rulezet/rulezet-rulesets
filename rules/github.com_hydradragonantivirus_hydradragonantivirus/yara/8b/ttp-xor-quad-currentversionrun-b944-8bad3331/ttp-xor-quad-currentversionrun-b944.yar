rule TTP_XOR_QUAD_CurrentVersionRun_b944 {
  strings:
    $key_b944 = { ea 2b [2] ce 25 [2] e5 09 [2] cb 2b [2] df 30 [2] d0 2a [2] ce 37 [2] cc 36 [2] d7 30 [2] cb 37 [2] d7 18 }

  condition:
    any of them
}