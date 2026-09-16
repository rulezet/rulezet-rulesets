rule TTP_XOR_QUAD_CurrentVersionRun_607e {
  strings:
    $key_607e = { 33 11 [2] 17 1f [2] 3c 33 [2] 12 11 [2] 06 0a [2] 09 10 [2] 17 0d [2] 15 0c [2] 0e 0a [2] 12 0d [2] 0e 22 }

  condition:
    any of them
}