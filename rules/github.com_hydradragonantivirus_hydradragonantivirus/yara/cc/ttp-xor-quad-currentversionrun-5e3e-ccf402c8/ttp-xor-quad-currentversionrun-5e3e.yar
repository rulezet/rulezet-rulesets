rule TTP_XOR_QUAD_CurrentVersionRun_5e3e {
  strings:
    $key_5e3e = { 0d 51 [2] 29 5f [2] 02 73 [2] 2c 51 [2] 38 4a [2] 37 50 [2] 29 4d [2] 2b 4c [2] 30 4a [2] 2c 4d [2] 30 62 }

  condition:
    any of them
}