rule TTP_XOR_QUAD_CurrentVersionRun_b91e {
  strings:
    $key_b91e = { ea 71 [2] ce 7f [2] e5 53 [2] cb 71 [2] df 6a [2] d0 70 [2] ce 6d [2] cc 6c [2] d7 6a [2] cb 6d [2] d7 42 }

  condition:
    any of them
}