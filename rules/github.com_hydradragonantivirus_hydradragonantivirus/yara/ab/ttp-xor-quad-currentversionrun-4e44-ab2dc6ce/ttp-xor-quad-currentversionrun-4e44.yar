rule TTP_XOR_QUAD_CurrentVersionRun_4e44 {
  strings:
    $key_4e44 = { 1d 2b [2] 39 25 [2] 12 09 [2] 3c 2b [2] 28 30 [2] 27 2a [2] 39 37 [2] 3b 36 [2] 20 30 [2] 3c 37 [2] 20 18 }

  condition:
    any of them
}