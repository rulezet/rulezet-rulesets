rule TTP_XOR_QUAD_CurrentVersionRun_b92d {
  strings:
    $key_b92d = { ea 42 [2] ce 4c [2] e5 60 [2] cb 42 [2] df 59 [2] d0 43 [2] ce 5e [2] cc 5f [2] d7 59 [2] cb 5e [2] d7 71 }

  condition:
    any of them
}