rule TTP_XOR_QUAD_CurrentVersionRun_b97f {
  strings:
    $key_b97f = { ea 10 [2] ce 1e [2] e5 32 [2] cb 10 [2] df 0b [2] d0 11 [2] ce 0c [2] cc 0d [2] d7 0b [2] cb 0c [2] d7 23 }

  condition:
    any of them
}