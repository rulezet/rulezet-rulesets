rule TTP_XOR_QUAD_CurrentVersionRun_5e1e {
  strings:
    $key_5e1e = { 0d 71 [2] 29 7f [2] 02 53 [2] 2c 71 [2] 38 6a [2] 37 70 [2] 29 6d [2] 2b 6c [2] 30 6a [2] 2c 6d [2] 30 42 }

  condition:
    any of them
}