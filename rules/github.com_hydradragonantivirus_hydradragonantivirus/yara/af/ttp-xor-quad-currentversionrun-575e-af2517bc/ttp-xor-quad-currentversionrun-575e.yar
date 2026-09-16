rule TTP_XOR_QUAD_CurrentVersionRun_575e {
  strings:
    $key_575e = { 04 31 [2] 20 3f [2] 0b 13 [2] 25 31 [2] 31 2a [2] 3e 30 [2] 20 2d [2] 22 2c [2] 39 2a [2] 25 2d [2] 39 02 }

  condition:
    any of them
}