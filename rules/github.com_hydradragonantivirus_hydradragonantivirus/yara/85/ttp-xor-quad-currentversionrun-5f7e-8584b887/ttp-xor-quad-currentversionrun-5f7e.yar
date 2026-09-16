rule TTP_XOR_QUAD_CurrentVersionRun_5f7e {
  strings:
    $key_5f7e = { 0c 11 [2] 28 1f [2] 03 33 [2] 2d 11 [2] 39 0a [2] 36 10 [2] 28 0d [2] 2a 0c [2] 31 0a [2] 2d 0d [2] 31 22 }

  condition:
    any of them
}