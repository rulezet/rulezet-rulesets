rule TTP_XOR_QUAD_CurrentVersionRun_b912 {
  strings:
    $key_b912 = { ea 7d [2] ce 73 [2] e5 5f [2] cb 7d [2] df 66 [2] d0 7c [2] ce 61 [2] cc 60 [2] d7 66 [2] cb 61 [2] d7 4e }

  condition:
    any of them
}