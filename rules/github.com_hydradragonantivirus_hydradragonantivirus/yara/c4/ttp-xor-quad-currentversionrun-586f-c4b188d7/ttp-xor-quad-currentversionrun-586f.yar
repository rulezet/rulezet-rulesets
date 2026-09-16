rule TTP_XOR_QUAD_CurrentVersionRun_586f {
  strings:
    $key_586f = { 0b 00 [2] 2f 0e [2] 04 22 [2] 2a 00 [2] 3e 1b [2] 31 01 [2] 2f 1c [2] 2d 1d [2] 36 1b [2] 2a 1c [2] 36 33 }

  condition:
    any of them
}