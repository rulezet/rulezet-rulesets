rule TTP_XOR_QUAD_CurrentVersionRun_b939 {
  strings:
    $key_b939 = { ea 56 [2] ce 58 [2] e5 74 [2] cb 56 [2] df 4d [2] d0 57 [2] ce 4a [2] cc 4b [2] d7 4d [2] cb 4a [2] d7 65 }

  condition:
    any of them
}