rule TTP_XOR_QUAD_CurrentVersionRun_b901 {
  strings:
    $key_b901 = { ea 6e [2] ce 60 [2] e5 4c [2] cb 6e [2] df 75 [2] d0 6f [2] ce 72 [2] cc 73 [2] d7 75 [2] cb 72 [2] d7 5d }

  condition:
    any of them
}