rule TTP_XOR_QUAD_CurrentVersionRun_746f {
  strings:
    $key_746f = { 27 00 [2] 03 0e [2] 28 22 [2] 06 00 [2] 12 1b [2] 1d 01 [2] 03 1c [2] 01 1d [2] 1a 1b [2] 06 1c [2] 1a 33 }

  condition:
    any of them
}