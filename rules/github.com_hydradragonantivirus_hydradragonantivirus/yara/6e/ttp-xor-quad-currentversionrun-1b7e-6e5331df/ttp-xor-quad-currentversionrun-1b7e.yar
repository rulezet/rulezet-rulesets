rule TTP_XOR_QUAD_CurrentVersionRun_1b7e {
  strings:
    $key_1b7e = { 48 11 [2] 6c 1f [2] 47 33 [2] 69 11 [2] 7d 0a [2] 72 10 [2] 6c 0d [2] 6e 0c [2] 75 0a [2] 69 0d [2] 75 22 }

  condition:
    any of them
}