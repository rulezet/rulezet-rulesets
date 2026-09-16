rule TTP_XOR_QUAD_CurrentVersionRun_5259 {
  strings:
    $key_5259 = { 01 36 [2] 25 38 [2] 0e 14 [2] 20 36 [2] 34 2d [2] 3b 37 [2] 25 2a [2] 27 2b [2] 3c 2d [2] 20 2a [2] 3c 05 }

  condition:
    any of them
}