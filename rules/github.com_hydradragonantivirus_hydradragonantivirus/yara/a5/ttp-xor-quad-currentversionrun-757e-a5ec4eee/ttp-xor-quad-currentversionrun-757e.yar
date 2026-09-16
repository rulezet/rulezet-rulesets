rule TTP_XOR_QUAD_CurrentVersionRun_757e {
  strings:
    $key_757e = { 26 11 [2] 02 1f [2] 29 33 [2] 07 11 [2] 13 0a [2] 1c 10 [2] 02 0d [2] 00 0c [2] 1b 0a [2] 07 0d [2] 1b 22 }

  condition:
    any of them
}