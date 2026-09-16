rule TTP_XOR_QUAD_CurrentVersionRun_3f5e {
  strings:
    $key_3f5e = { 6c 31 [2] 48 3f [2] 63 13 [2] 4d 31 [2] 59 2a [2] 56 30 [2] 48 2d [2] 4a 2c [2] 51 2a [2] 4d 2d [2] 51 02 }

  condition:
    any of them
}