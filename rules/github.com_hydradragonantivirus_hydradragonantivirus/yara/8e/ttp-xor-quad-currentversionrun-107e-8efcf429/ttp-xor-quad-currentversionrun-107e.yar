rule TTP_XOR_QUAD_CurrentVersionRun_107e {
  strings:
    $key_107e = { 43 11 [2] 67 1f [2] 4c 33 [2] 62 11 [2] 76 0a [2] 79 10 [2] 67 0d [2] 65 0c [2] 7e 0a [2] 62 0d [2] 7e 22 }

  condition:
    any of them
}