rule TTP_XOR_QUAD_CurrentVersionRun_0c7e {
  strings:
    $key_0c7e = { 5f 11 [2] 7b 1f [2] 50 33 [2] 7e 11 [2] 6a 0a [2] 65 10 [2] 7b 0d [2] 79 0c [2] 62 0a [2] 7e 0d [2] 62 22 }

  condition:
    any of them
}