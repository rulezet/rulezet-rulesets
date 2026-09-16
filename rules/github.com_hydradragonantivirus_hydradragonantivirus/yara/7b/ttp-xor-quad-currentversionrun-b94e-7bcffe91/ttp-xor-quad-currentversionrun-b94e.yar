rule TTP_XOR_QUAD_CurrentVersionRun_b94e {
  strings:
    $key_b94e = { ea 21 [2] ce 2f [2] e5 03 [2] cb 21 [2] df 3a [2] d0 20 [2] ce 3d [2] cc 3c [2] d7 3a [2] cb 3d [2] d7 12 }

  condition:
    any of them
}