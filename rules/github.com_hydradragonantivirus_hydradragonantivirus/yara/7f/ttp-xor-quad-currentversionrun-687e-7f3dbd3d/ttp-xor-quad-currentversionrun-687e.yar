rule TTP_XOR_QUAD_CurrentVersionRun_687e {
  strings:
    $key_687e = { 3b 11 [2] 1f 1f [2] 34 33 [2] 1a 11 [2] 0e 0a [2] 01 10 [2] 1f 0d [2] 1d 0c [2] 06 0a [2] 1a 0d [2] 06 22 }

  condition:
    any of them
}