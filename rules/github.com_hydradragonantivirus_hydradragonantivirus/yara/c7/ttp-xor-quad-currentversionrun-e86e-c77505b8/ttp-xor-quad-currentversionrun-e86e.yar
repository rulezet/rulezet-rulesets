rule TTP_XOR_QUAD_CurrentVersionRun_e86e {
  strings:
    $key_e86e = { bb 01 [2] 9f 0f [2] b4 23 [2] 9a 01 [2] 8e 1a [2] 81 00 [2] 9f 1d [2] 9d 1c [2] 86 1a [2] 9a 1d [2] 86 32 }

  condition:
    any of them
}