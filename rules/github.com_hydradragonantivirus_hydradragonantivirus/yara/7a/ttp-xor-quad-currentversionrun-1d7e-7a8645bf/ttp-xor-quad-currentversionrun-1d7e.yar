rule TTP_XOR_QUAD_CurrentVersionRun_1d7e {
  strings:
    $key_1d7e = { 4e 11 [2] 6a 1f [2] 41 33 [2] 6f 11 [2] 7b 0a [2] 74 10 [2] 6a 0d [2] 68 0c [2] 73 0a [2] 6f 0d [2] 73 22 }

  condition:
    any of them
}