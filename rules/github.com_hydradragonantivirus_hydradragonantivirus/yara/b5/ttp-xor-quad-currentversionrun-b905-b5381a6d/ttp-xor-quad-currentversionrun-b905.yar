rule TTP_XOR_QUAD_CurrentVersionRun_b905 {
  strings:
    $key_b905 = { ea 6a [2] ce 64 [2] e5 48 [2] cb 6a [2] df 71 [2] d0 6b [2] ce 76 [2] cc 77 [2] d7 71 [2] cb 76 [2] d7 59 }

  condition:
    any of them
}