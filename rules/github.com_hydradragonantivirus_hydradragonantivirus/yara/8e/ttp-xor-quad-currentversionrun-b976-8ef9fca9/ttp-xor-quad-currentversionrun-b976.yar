rule TTP_XOR_QUAD_CurrentVersionRun_b976 {
  strings:
    $key_b976 = { ea 19 [2] ce 17 [2] e5 3b [2] cb 19 [2] df 02 [2] d0 18 [2] ce 05 [2] cc 04 [2] d7 02 [2] cb 05 [2] d7 2a }

  condition:
    any of them
}