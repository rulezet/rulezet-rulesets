rule TTP_XOR_QUAD_CurrentVersionRun_4959 {
  strings:
    $key_4959 = { 1a 36 [2] 3e 38 [2] 15 14 [2] 3b 36 [2] 2f 2d [2] 20 37 [2] 3e 2a [2] 3c 2b [2] 27 2d [2] 3b 2a [2] 27 05 }

  condition:
    any of them
}