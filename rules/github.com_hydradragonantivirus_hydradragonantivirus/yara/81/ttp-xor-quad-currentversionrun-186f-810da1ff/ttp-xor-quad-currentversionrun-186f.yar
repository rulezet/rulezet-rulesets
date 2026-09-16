rule TTP_XOR_QUAD_CurrentVersionRun_186f {
  strings:
    $key_186f = { 4b 00 [2] 6f 0e [2] 44 22 [2] 6a 00 [2] 7e 1b [2] 71 01 [2] 6f 1c [2] 6d 1d [2] 76 1b [2] 6a 1c [2] 76 33 }

  condition:
    any of them
}