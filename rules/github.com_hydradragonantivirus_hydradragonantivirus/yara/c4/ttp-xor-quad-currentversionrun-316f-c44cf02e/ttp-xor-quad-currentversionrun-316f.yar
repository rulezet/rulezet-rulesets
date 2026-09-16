rule TTP_XOR_QUAD_CurrentVersionRun_316f {
  strings:
    $key_316f = { 62 00 [2] 46 0e [2] 6d 22 [2] 43 00 [2] 57 1b [2] 58 01 [2] 46 1c [2] 44 1d [2] 5f 1b [2] 43 1c [2] 5f 33 }

  condition:
    any of them
}