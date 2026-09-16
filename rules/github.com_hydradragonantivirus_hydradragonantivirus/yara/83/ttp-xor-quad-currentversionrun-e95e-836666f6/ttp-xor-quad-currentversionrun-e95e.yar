rule TTP_XOR_QUAD_CurrentVersionRun_e95e {
  strings:
    $key_e95e = { ba 31 [2] 9e 3f [2] b5 13 [2] 9b 31 [2] 8f 2a [2] 80 30 [2] 9e 2d [2] 9c 2c [2] 87 2a [2] 9b 2d [2] 87 02 }

  condition:
    any of them
}