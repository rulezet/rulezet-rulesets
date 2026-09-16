rule TTP_XOR_QUAD_CurrentVersionRun_336f {
  strings:
    $key_336f = { 60 00 [2] 44 0e [2] 6f 22 [2] 41 00 [2] 55 1b [2] 5a 01 [2] 44 1c [2] 46 1d [2] 5d 1b [2] 41 1c [2] 5d 33 }

  condition:
    any of them
}