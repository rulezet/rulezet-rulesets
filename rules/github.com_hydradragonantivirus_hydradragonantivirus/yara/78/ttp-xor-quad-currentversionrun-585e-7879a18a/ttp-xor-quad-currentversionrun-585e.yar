rule TTP_XOR_QUAD_CurrentVersionRun_585e {
  strings:
    $key_585e = { 0b 31 [2] 2f 3f [2] 04 13 [2] 2a 31 [2] 3e 2a [2] 31 30 [2] 2f 2d [2] 2d 2c [2] 36 2a [2] 2a 2d [2] 36 02 }

  condition:
    any of them
}