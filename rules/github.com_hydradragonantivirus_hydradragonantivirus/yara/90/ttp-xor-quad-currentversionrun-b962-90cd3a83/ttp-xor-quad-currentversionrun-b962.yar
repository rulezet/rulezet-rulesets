rule TTP_XOR_QUAD_CurrentVersionRun_b962 {
  strings:
    $key_b962 = { ea 0d [2] ce 03 [2] e5 2f [2] cb 0d [2] df 16 [2] d0 0c [2] ce 11 [2] cc 10 [2] d7 16 [2] cb 11 [2] d7 3e }

  condition:
    any of them
}