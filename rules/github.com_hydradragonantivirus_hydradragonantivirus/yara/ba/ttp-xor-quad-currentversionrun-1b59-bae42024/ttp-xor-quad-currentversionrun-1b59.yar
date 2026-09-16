rule TTP_XOR_QUAD_CurrentVersionRun_1b59 {
  strings:
    $key_1b59 = { 48 36 [2] 6c 38 [2] 47 14 [2] 69 36 [2] 7d 2d [2] 72 37 [2] 6c 2a [2] 6e 2b [2] 75 2d [2] 69 2a [2] 75 05 }

  condition:
    any of them
}