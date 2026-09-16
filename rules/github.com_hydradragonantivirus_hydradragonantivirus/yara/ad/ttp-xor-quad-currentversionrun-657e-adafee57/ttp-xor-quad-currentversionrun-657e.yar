rule TTP_XOR_QUAD_CurrentVersionRun_657e {
  strings:
    $key_657e = { 36 11 [2] 12 1f [2] 39 33 [2] 17 11 [2] 03 0a [2] 0c 10 [2] 12 0d [2] 10 0c [2] 0b 0a [2] 17 0d [2] 0b 22 }

  condition:
    any of them
}