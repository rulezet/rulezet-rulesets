rule TTP_XOR_QUAD_CurrentVersionRun_427e {
  strings:
    $key_427e = { 11 11 [2] 35 1f [2] 1e 33 [2] 30 11 [2] 24 0a [2] 2b 10 [2] 35 0d [2] 37 0c [2] 2c 0a [2] 30 0d [2] 2c 22 }

  condition:
    any of them
}