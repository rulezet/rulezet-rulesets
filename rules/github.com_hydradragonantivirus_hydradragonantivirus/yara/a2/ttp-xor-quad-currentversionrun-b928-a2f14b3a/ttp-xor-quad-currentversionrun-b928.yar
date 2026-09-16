rule TTP_XOR_QUAD_CurrentVersionRun_b928 {
  strings:
    $key_b928 = { ea 47 [2] ce 49 [2] e5 65 [2] cb 47 [2] df 5c [2] d0 46 [2] ce 5b [2] cc 5a [2] d7 5c [2] cb 5b [2] d7 74 }

  condition:
    any of them
}