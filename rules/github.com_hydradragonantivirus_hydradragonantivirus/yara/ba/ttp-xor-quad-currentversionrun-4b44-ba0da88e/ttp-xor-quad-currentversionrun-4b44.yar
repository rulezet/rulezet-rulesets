rule TTP_XOR_QUAD_CurrentVersionRun_4b44 {
  strings:
    $key_4b44 = { 18 2b [2] 3c 25 [2] 17 09 [2] 39 2b [2] 2d 30 [2] 22 2a [2] 3c 37 [2] 3e 36 [2] 25 30 [2] 39 37 [2] 25 18 }

  condition:
    any of them
}