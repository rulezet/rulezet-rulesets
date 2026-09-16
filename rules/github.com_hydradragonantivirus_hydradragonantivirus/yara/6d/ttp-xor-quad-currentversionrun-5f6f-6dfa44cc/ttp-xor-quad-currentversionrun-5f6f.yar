rule TTP_XOR_QUAD_CurrentVersionRun_5f6f {
  strings:
    $key_5f6f = { 0c 00 [2] 28 0e [2] 03 22 [2] 2d 00 [2] 39 1b [2] 36 01 [2] 28 1c [2] 2a 1d [2] 31 1b [2] 2d 1c [2] 31 33 }

  condition:
    any of them
}