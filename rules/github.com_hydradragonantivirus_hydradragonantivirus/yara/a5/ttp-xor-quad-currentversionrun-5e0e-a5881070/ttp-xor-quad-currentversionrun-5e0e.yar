rule TTP_XOR_QUAD_CurrentVersionRun_5e0e {
  strings:
    $key_5e0e = { 0d 61 [2] 29 6f [2] 02 43 [2] 2c 61 [2] 38 7a [2] 37 60 [2] 29 7d [2] 2b 7c [2] 30 7a [2] 2c 7d [2] 30 52 }

  condition:
    any of them
}