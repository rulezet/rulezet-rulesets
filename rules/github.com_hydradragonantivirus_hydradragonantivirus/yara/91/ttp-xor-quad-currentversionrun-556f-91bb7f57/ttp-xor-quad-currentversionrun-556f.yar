rule TTP_XOR_QUAD_CurrentVersionRun_556f {
  strings:
    $key_556f = { 06 00 [2] 22 0e [2] 09 22 [2] 27 00 [2] 33 1b [2] 3c 01 [2] 22 1c [2] 20 1d [2] 3b 1b [2] 27 1c [2] 3b 33 }

  condition:
    any of them
}