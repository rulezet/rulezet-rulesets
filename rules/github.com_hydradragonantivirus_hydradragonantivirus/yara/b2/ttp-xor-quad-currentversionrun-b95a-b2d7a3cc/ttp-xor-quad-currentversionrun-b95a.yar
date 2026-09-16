rule TTP_XOR_QUAD_CurrentVersionRun_b95a {
  strings:
    $key_b95a = { ea 35 [2] ce 3b [2] e5 17 [2] cb 35 [2] df 2e [2] d0 34 [2] ce 29 [2] cc 28 [2] d7 2e [2] cb 29 [2] d7 06 }

  condition:
    any of them
}