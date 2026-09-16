rule TTP_XOR_QUAD_CurrentVersionRun_b90e {
  strings:
    $key_b90e = { ea 61 [2] ce 6f [2] e5 43 [2] cb 61 [2] df 7a [2] d0 60 [2] ce 7d [2] cc 7c [2] d7 7a [2] cb 7d [2] d7 52 }

  condition:
    any of them
}