rule TTP_XOR_QUAD_CurrentVersionRun_b95b {
  strings:
    $key_b95b = { ea 34 [2] ce 3a [2] e5 16 [2] cb 34 [2] df 2f [2] d0 35 [2] ce 28 [2] cc 29 [2] d7 2f [2] cb 28 [2] d7 07 }

  condition:
    any of them
}