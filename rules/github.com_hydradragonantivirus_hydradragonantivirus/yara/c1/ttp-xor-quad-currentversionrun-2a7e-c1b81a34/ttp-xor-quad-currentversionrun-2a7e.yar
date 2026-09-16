rule TTP_XOR_QUAD_CurrentVersionRun_2a7e {
  strings:
    $key_2a7e = { 79 11 [2] 5d 1f [2] 76 33 [2] 58 11 [2] 4c 0a [2] 43 10 [2] 5d 0d [2] 5f 0c [2] 44 0a [2] 58 0d [2] 44 22 }

  condition:
    any of them
}