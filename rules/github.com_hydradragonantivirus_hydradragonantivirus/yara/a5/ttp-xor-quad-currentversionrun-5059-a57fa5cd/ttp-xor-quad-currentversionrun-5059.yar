rule TTP_XOR_QUAD_CurrentVersionRun_5059 {
  strings:
    $key_5059 = { 03 36 [2] 27 38 [2] 0c 14 [2] 22 36 [2] 36 2d [2] 39 37 [2] 27 2a [2] 25 2b [2] 3e 2d [2] 22 2a [2] 3e 05 }

  condition:
    any of them
}