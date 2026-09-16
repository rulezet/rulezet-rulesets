rule TTP_XOR_QUAD_CurrentVersionRun_2f7e {
  strings:
    $key_2f7e = { 7c 11 [2] 58 1f [2] 73 33 [2] 5d 11 [2] 49 0a [2] 46 10 [2] 58 0d [2] 5a 0c [2] 41 0a [2] 5d 0d [2] 41 22 }

  condition:
    any of them
}