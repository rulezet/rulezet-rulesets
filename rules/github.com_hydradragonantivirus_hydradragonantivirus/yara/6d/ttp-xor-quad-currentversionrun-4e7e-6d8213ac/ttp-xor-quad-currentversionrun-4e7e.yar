rule TTP_XOR_QUAD_CurrentVersionRun_4e7e {
  strings:
    $key_4e7e = { 1d 11 [2] 39 1f [2] 12 33 [2] 3c 11 [2] 28 0a [2] 27 10 [2] 39 0d [2] 3b 0c [2] 20 0a [2] 3c 0d [2] 20 22 }

  condition:
    any of them
}