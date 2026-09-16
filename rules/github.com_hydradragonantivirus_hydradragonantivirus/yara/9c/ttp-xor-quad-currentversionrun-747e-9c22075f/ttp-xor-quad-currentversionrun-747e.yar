rule TTP_XOR_QUAD_CurrentVersionRun_747e {
  strings:
    $key_747e = { 27 11 [2] 03 1f [2] 28 33 [2] 06 11 [2] 12 0a [2] 1d 10 [2] 03 0d [2] 01 0c [2] 1a 0a [2] 06 0d [2] 1a 22 }

  condition:
    any of them
}