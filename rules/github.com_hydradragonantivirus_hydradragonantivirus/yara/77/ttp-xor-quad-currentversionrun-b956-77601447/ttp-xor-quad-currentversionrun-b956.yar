rule TTP_XOR_QUAD_CurrentVersionRun_b956 {
  strings:
    $key_b956 = { ea 39 [2] ce 37 [2] e5 1b [2] cb 39 [2] df 22 [2] d0 38 [2] ce 25 [2] cc 24 [2] d7 22 [2] cb 25 [2] d7 0a }

  condition:
    any of them
}