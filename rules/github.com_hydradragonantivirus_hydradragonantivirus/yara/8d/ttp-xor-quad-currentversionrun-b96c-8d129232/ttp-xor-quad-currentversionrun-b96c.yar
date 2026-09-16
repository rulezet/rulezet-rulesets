rule TTP_XOR_QUAD_CurrentVersionRun_b96c {
  strings:
    $key_b96c = { ea 03 [2] ce 0d [2] e5 21 [2] cb 03 [2] df 18 [2] d0 02 [2] ce 1f [2] cc 1e [2] d7 18 [2] cb 1f [2] d7 30 }

  condition:
    any of them
}