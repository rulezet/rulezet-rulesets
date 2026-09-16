rule TTP_XOR_QUAD_CurrentVersionRun_1f7e {
  strings:
    $key_1f7e = { 4c 11 [2] 68 1f [2] 43 33 [2] 6d 11 [2] 79 0a [2] 76 10 [2] 68 0d [2] 6a 0c [2] 71 0a [2] 6d 0d [2] 71 22 }

  condition:
    any of them
}