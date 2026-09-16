rule TTP_XOR_QUAD_CurrentVersionRun_b96d {
  strings:
    $key_b96d = { ea 02 [2] ce 0c [2] e5 20 [2] cb 02 [2] df 19 [2] d0 03 [2] ce 1e [2] cc 1f [2] d7 19 [2] cb 1e [2] d7 31 }

  condition:
    any of them
}