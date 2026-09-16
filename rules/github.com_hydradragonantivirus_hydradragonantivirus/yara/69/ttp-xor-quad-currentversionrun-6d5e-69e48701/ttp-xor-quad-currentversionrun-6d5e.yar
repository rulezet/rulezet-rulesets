rule TTP_XOR_QUAD_CurrentVersionRun_6d5e {
  strings:
    $key_6d5e = { 3e 31 [2] 1a 3f [2] 31 13 [2] 1f 31 [2] 0b 2a [2] 04 30 [2] 1a 2d [2] 18 2c [2] 03 2a [2] 1f 2d [2] 03 02 }

  condition:
    any of them
}