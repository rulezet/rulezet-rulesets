rule TTP_XOR_QUAD_CurrentVersionRun_b923 {
  strings:
    $key_b923 = { ea 4c [2] ce 42 [2] e5 6e [2] cb 4c [2] df 57 [2] d0 4d [2] ce 50 [2] cc 51 [2] d7 57 [2] cb 50 [2] d7 7f }

  condition:
    any of them
}