rule TTP_XOR_QUAD_CurrentVersionRun_b949 {
  strings:
    $key_b949 = { ea 26 [2] ce 28 [2] e5 04 [2] cb 26 [2] df 3d [2] d0 27 [2] ce 3a [2] cc 3b [2] d7 3d [2] cb 3a [2] d7 15 }

  condition:
    any of them
}