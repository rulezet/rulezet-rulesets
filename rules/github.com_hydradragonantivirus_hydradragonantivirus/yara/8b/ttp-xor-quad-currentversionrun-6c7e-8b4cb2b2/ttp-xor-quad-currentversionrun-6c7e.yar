rule TTP_XOR_QUAD_CurrentVersionRun_6c7e {
  strings:
    $key_6c7e = { 3f 11 [2] 1b 1f [2] 30 33 [2] 1e 11 [2] 0a 0a [2] 05 10 [2] 1b 0d [2] 19 0c [2] 02 0a [2] 1e 0d [2] 02 22 }

  condition:
    any of them
}