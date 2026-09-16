rule TTP_XOR_QUAD_CurrentVersionRun_b955 {
  strings:
    $key_b955 = { ea 3a [2] ce 34 [2] e5 18 [2] cb 3a [2] df 21 [2] d0 3b [2] ce 26 [2] cc 27 [2] d7 21 [2] cb 26 [2] d7 09 }

  condition:
    any of them
}