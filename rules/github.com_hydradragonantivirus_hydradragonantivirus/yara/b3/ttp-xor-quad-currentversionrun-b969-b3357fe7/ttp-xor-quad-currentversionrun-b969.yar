rule TTP_XOR_QUAD_CurrentVersionRun_b969 {
  strings:
    $key_b969 = { ea 06 [2] ce 08 [2] e5 24 [2] cb 06 [2] df 1d [2] d0 07 [2] ce 1a [2] cc 1b [2] d7 1d [2] cb 1a [2] d7 35 }

  condition:
    any of them
}