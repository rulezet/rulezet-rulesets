rule TTP_XOR_QUAD_CurrentVersionRun_366f {
  strings:
    $key_366f = { 65 00 [2] 41 0e [2] 6a 22 [2] 44 00 [2] 50 1b [2] 5f 01 [2] 41 1c [2] 43 1d [2] 58 1b [2] 44 1c [2] 58 33 }

  condition:
    any of them
}