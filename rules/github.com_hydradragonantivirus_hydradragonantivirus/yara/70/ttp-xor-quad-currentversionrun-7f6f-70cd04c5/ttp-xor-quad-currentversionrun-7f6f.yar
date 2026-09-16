rule TTP_XOR_QUAD_CurrentVersionRun_7f6f {
  strings:
    $key_7f6f = { 2c 00 [2] 08 0e [2] 23 22 [2] 0d 00 [2] 19 1b [2] 16 01 [2] 08 1c [2] 0a 1d [2] 11 1b [2] 0d 1c [2] 11 33 }

  condition:
    any of them
}