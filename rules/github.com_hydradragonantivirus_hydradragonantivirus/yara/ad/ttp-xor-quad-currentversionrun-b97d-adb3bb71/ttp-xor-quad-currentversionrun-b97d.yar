rule TTP_XOR_QUAD_CurrentVersionRun_b97d {
  strings:
    $key_b97d = { ea 12 [2] ce 1c [2] e5 30 [2] cb 12 [2] df 09 [2] d0 13 [2] ce 0e [2] cc 0f [2] d7 09 [2] cb 0e [2] d7 21 }

  condition:
    any of them
}