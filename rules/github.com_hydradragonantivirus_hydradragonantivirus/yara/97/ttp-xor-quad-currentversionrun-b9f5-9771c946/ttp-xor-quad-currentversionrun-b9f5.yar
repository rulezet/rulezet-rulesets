rule TTP_XOR_QUAD_CurrentVersionRun_b9f5 {
  strings:
    $key_b9f5 = { ea 9a [2] ce 94 [2] e5 b8 [2] cb 9a [2] df 81 [2] d0 9b [2] ce 86 [2] cc 87 [2] d7 81 [2] cb 86 [2] d7 a9 }

  condition:
    any of them
}