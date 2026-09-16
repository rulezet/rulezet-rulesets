rule TTP_XOR_QUAD_CurrentVersionRun_5a7e {
  strings:
    $key_5a7e = { 09 11 [2] 2d 1f [2] 06 33 [2] 28 11 [2] 3c 0a [2] 33 10 [2] 2d 0d [2] 2f 0c [2] 34 0a [2] 28 0d [2] 34 22 }

  condition:
    any of them
}