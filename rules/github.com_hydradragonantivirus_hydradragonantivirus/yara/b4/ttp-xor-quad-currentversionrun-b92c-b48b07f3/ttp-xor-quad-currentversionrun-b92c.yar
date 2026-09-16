rule TTP_XOR_QUAD_CurrentVersionRun_b92c {
  strings:
    $key_b92c = { ea 43 [2] ce 4d [2] e5 61 [2] cb 43 [2] df 58 [2] d0 42 [2] ce 5f [2] cc 5e [2] d7 58 [2] cb 5f [2] d7 70 }

  condition:
    any of them
}