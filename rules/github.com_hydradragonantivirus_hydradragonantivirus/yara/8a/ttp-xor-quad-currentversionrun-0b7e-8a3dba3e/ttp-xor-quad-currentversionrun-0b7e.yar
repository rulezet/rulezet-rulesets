rule TTP_XOR_QUAD_CurrentVersionRun_0b7e {
  strings:
    $key_0b7e = { 58 11 [2] 7c 1f [2] 57 33 [2] 79 11 [2] 6d 0a [2] 62 10 [2] 7c 0d [2] 7e 0c [2] 65 0a [2] 79 0d [2] 65 22 }

  condition:
    any of them
}