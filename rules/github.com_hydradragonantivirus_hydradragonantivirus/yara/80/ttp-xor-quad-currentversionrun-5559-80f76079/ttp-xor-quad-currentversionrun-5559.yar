rule TTP_XOR_QUAD_CurrentVersionRun_5559 {
  strings:
    $key_5559 = { 06 36 [2] 22 38 [2] 09 14 [2] 27 36 [2] 33 2d [2] 3c 37 [2] 22 2a [2] 20 2b [2] 3b 2d [2] 27 2a [2] 3b 05 }

  condition:
    any of them
}