rule TTP_XOR_QUAD_CurrentVersionRun_0059 {
  strings:
    $key_0059 = { 53 36 [2] 77 38 [2] 5c 14 [2] 72 36 [2] 66 2d [2] 69 37 [2] 77 2a [2] 75 2b [2] 6e 2d [2] 72 2a [2] 6e 05 }

  condition:
    any of them
}