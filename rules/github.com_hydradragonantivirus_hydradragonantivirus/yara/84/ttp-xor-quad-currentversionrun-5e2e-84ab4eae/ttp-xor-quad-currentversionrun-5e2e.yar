rule TTP_XOR_QUAD_CurrentVersionRun_5e2e {
  strings:
    $key_5e2e = { 0d 41 [2] 29 4f [2] 02 63 [2] 2c 41 [2] 38 5a [2] 37 40 [2] 29 5d [2] 2b 5c [2] 30 5a [2] 2c 5d [2] 30 72 }

  condition:
    any of them
}