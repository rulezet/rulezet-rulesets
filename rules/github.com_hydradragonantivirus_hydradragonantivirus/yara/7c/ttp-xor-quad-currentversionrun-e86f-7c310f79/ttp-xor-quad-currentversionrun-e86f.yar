rule TTP_XOR_QUAD_CurrentVersionRun_e86f {
  strings:
    $key_e86f = { bb 00 [2] 9f 0e [2] b4 22 [2] 9a 00 [2] 8e 1b [2] 81 01 [2] 9f 1c [2] 9d 1d [2] 86 1b [2] 9a 1c [2] 86 33 }

  condition:
    any of them
}