rule TTP_XOR_QUAD_CurrentVersionRun_436f {
  strings:
    $key_436f = { 10 00 [2] 34 0e [2] 1f 22 [2] 31 00 [2] 25 1b [2] 2a 01 [2] 34 1c [2] 36 1d [2] 2d 1b [2] 31 1c [2] 2d 33 }

  condition:
    any of them
}