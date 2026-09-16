rule TTP_XOR_QUAD_CurrentVersionRun_2d59 {
  strings:
    $key_2d59 = { 7e 36 [2] 5a 38 [2] 71 14 [2] 5f 36 [2] 4b 2d [2] 44 37 [2] 5a 2a [2] 58 2b [2] 43 2d [2] 5f 2a [2] 43 05 }

  condition:
    any of them
}