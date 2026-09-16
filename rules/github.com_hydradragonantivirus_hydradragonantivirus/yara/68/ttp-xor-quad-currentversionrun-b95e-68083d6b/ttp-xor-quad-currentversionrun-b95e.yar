rule TTP_XOR_QUAD_CurrentVersionRun_b95e {
  strings:
    $key_b95e = { ea 31 [2] ce 3f [2] e5 13 [2] cb 31 [2] df 2a [2] d0 30 [2] ce 2d [2] cc 2c [2] d7 2a [2] cb 2d [2] d7 02 }

  condition:
    any of them
}