rule TTP_XOR_QUAD_CurrentVersionRun_4d7e {
  strings:
    $key_4d7e = { 1e 11 [2] 3a 1f [2] 11 33 [2] 3f 11 [2] 2b 0a [2] 24 10 [2] 3a 0d [2] 38 0c [2] 23 0a [2] 3f 0d [2] 23 22 }

  condition:
    any of them
}