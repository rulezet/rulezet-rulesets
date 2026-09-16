rule TTP_XOR_QUAD_CurrentVersionRun_b9f4 {
  strings:
    $key_b9f4 = { ea 9b [2] ce 95 [2] e5 b9 [2] cb 9b [2] df 80 [2] d0 9a [2] ce 87 [2] cc 86 [2] d7 80 [2] cb 87 [2] d7 a8 }

  condition:
    any of them
}