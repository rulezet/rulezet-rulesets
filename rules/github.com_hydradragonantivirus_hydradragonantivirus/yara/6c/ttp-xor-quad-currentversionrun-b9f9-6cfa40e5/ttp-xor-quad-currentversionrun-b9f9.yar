rule TTP_XOR_QUAD_CurrentVersionRun_b9f9 {
  strings:
    $key_b9f9 = { ea 96 [2] ce 98 [2] e5 b4 [2] cb 96 [2] df 8d [2] d0 97 [2] ce 8a [2] cc 8b [2] d7 8d [2] cb 8a [2] d7 a5 }

  condition:
    any of them
}