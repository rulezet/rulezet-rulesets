rule TTP_XOR_QUAD_CurrentVersionRun_036f {
  strings:
    $key_036f = { 50 00 [2] 74 0e [2] 5f 22 [2] 71 00 [2] 65 1b [2] 6a 01 [2] 74 1c [2] 76 1d [2] 6d 1b [2] 71 1c [2] 6d 33 }

  condition:
    any of them
}