rule TTP_XOR_QUAD_CurrentVersionRun_421e {
  strings:
    $key_421e = { 11 71 [2] 35 7f [2] 1e 53 [2] 30 71 [2] 24 6a [2] 2b 70 [2] 35 6d [2] 37 6c [2] 2c 6a [2] 30 6d [2] 2c 42 }

  condition:
    any of them
}