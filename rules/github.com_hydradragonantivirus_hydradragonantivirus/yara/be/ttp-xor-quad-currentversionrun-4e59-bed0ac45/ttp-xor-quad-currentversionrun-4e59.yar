rule TTP_XOR_QUAD_CurrentVersionRun_4e59 {
  strings:
    $key_4e59 = { 1d 36 [2] 39 38 [2] 12 14 [2] 3c 36 [2] 28 2d [2] 27 37 [2] 39 2a [2] 3b 2b [2] 20 2d [2] 3c 2a [2] 20 05 }

  condition:
    any of them
}