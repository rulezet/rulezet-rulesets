rule TTP_XOR_QUAD_CurrentVersionRun_0d5e {
  strings:
    $key_0d5e = { 5e 31 [2] 7a 3f [2] 51 13 [2] 7f 31 [2] 6b 2a [2] 64 30 [2] 7a 2d [2] 78 2c [2] 63 2a [2] 7f 2d [2] 63 02 }

  condition:
    any of them
}