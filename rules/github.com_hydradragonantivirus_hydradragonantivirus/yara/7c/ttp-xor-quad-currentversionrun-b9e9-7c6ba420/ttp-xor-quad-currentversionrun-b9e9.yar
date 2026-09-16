rule TTP_XOR_QUAD_CurrentVersionRun_b9e9 {
  strings:
    $key_b9e9 = { ea 86 [2] ce 88 [2] e5 a4 [2] cb 86 [2] df 9d [2] d0 87 [2] ce 9a [2] cc 9b [2] d7 9d [2] cb 9a [2] d7 b5 }

  condition:
    any of them
}