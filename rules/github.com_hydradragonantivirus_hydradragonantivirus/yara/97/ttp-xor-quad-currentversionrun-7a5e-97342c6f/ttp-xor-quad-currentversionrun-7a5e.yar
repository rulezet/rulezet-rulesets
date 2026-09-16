rule TTP_XOR_QUAD_CurrentVersionRun_7a5e {
  strings:
    $key_7a5e = { 29 31 [2] 0d 3f [2] 26 13 [2] 08 31 [2] 1c 2a [2] 13 30 [2] 0d 2d [2] 0f 2c [2] 14 2a [2] 08 2d [2] 14 02 }

  condition:
    any of them
}