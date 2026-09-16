rule TTP_XOR_QUAD_CurrentVersionRun_7b7e {
  strings:
    $key_7b7e = { 28 11 [2] 0c 1f [2] 27 33 [2] 09 11 [2] 1d 0a [2] 12 10 [2] 0c 0d [2] 0e 0c [2] 15 0a [2] 09 0d [2] 15 22 }

  condition:
    any of them
}