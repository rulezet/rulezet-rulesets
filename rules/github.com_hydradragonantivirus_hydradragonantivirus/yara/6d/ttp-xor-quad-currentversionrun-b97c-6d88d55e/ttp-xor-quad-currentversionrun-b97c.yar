rule TTP_XOR_QUAD_CurrentVersionRun_b97c {
  strings:
    $key_b97c = { ea 13 [2] ce 1d [2] e5 31 [2] cb 13 [2] df 08 [2] d0 12 [2] ce 0f [2] cc 0e [2] d7 08 [2] cb 0f [2] d7 20 }

  condition:
    any of them
}