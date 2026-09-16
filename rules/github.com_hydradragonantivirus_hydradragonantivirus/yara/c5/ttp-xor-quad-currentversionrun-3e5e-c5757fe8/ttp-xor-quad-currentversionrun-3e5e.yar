rule TTP_XOR_QUAD_CurrentVersionRun_3e5e {
  strings:
    $key_3e5e = { 6d 31 [2] 49 3f [2] 62 13 [2] 4c 31 [2] 58 2a [2] 57 30 [2] 49 2d [2] 4b 2c [2] 50 2a [2] 4c 2d [2] 50 02 }

  condition:
    any of them
}