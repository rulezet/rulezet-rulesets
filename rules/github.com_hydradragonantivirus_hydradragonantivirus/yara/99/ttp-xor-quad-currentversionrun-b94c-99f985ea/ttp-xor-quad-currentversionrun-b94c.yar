rule TTP_XOR_QUAD_CurrentVersionRun_b94c {
  strings:
    $key_b94c = { ea 23 [2] ce 2d [2] e5 01 [2] cb 23 [2] df 38 [2] d0 22 [2] ce 3f [2] cc 3e [2] d7 38 [2] cb 3f [2] d7 10 }

  condition:
    any of them
}