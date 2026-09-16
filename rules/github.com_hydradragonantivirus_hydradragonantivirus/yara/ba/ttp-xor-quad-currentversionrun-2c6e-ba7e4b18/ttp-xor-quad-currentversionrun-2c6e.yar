rule TTP_XOR_QUAD_CurrentVersionRun_2c6e {
  strings:
    $key_2c6e = { 7f 01 [2] 5b 0f [2] 70 23 [2] 5e 01 [2] 4a 1a [2] 45 00 [2] 5b 1d [2] 59 1c [2] 42 1a [2] 5e 1d [2] 42 32 }

  condition:
    any of them
}