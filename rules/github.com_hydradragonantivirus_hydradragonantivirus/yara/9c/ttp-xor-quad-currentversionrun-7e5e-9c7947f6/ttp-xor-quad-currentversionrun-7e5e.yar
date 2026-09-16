rule TTP_XOR_QUAD_CurrentVersionRun_7e5e {
  strings:
    $key_7e5e = { 2d 31 [2] 09 3f [2] 22 13 [2] 0c 31 [2] 18 2a [2] 17 30 [2] 09 2d [2] 0b 2c [2] 10 2a [2] 0c 2d [2] 10 02 }

  condition:
    any of them
}