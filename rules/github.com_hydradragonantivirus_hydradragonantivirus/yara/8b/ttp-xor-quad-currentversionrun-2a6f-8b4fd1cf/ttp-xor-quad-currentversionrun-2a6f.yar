rule TTP_XOR_QUAD_CurrentVersionRun_2a6f {
  strings:
    $key_2a6f = { 79 00 [2] 5d 0e [2] 76 22 [2] 58 00 [2] 4c 1b [2] 43 01 [2] 5d 1c [2] 5f 1d [2] 44 1b [2] 58 1c [2] 44 33 }

  condition:
    any of them
}