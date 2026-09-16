rule TTP_XOR_QUAD_CurrentVersionRun_b90a {
  strings:
    $key_b90a = { ea 65 [2] ce 6b [2] e5 47 [2] cb 65 [2] df 7e [2] d0 64 [2] ce 79 [2] cc 78 [2] d7 7e [2] cb 79 [2] d7 56 }

  condition:
    any of them
}