rule TTP_XOR_QUAD_CurrentVersionRun_407e {
  strings:
    $key_407e = { 13 11 [2] 37 1f [2] 1c 33 [2] 32 11 [2] 26 0a [2] 29 10 [2] 37 0d [2] 35 0c [2] 2e 0a [2] 32 0d [2] 2e 22 }

  condition:
    any of them
}