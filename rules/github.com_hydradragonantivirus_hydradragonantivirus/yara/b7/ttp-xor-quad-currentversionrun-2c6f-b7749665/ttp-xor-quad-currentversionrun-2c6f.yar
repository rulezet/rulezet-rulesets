rule TTP_XOR_QUAD_CurrentVersionRun_2c6f {
  strings:
    $key_2c6f = { 7f 00 [2] 5b 0e [2] 70 22 [2] 5e 00 [2] 4a 1b [2] 45 01 [2] 5b 1c [2] 59 1d [2] 42 1b [2] 5e 1c [2] 42 33 }

  condition:
    any of them
}