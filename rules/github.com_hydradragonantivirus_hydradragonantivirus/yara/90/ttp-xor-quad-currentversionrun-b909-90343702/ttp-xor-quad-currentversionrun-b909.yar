rule TTP_XOR_QUAD_CurrentVersionRun_b909 {
  strings:
    $key_b909 = { ea 66 [2] ce 68 [2] e5 44 [2] cb 66 [2] df 7d [2] d0 67 [2] ce 7a [2] cc 7b [2] d7 7d [2] cb 7a [2] d7 55 }

  condition:
    any of them
}