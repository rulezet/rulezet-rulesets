rule TTP_XOR_QUAD_CurrentVersionRun_2d6f {
  strings:
    $key_2d6f = { 7e 00 [2] 5a 0e [2] 71 22 [2] 5f 00 [2] 4b 1b [2] 44 01 [2] 5a 1c [2] 58 1d [2] 43 1b [2] 5f 1c [2] 43 33 }

  condition:
    any of them
}