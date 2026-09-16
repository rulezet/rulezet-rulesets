rule TTP_XOR_QUAD_CurrentVersionRun_7e7e {
  strings:
    $key_7e7e = { 2d 11 [2] 09 1f [2] 22 33 [2] 0c 11 [2] 18 0a [2] 17 10 [2] 09 0d [2] 0b 0c [2] 10 0a [2] 0c 0d [2] 10 22 }

  condition:
    any of them
}