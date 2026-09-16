rule TTP_XOR_QUAD_CurrentVersionRun_4e79 {
  strings:
    $key_4e79 = { 1d 16 [2] 39 18 [2] 12 34 [2] 3c 16 [2] 28 0d [2] 27 17 [2] 39 0a [2] 3b 0b [2] 20 0d [2] 3c 0a [2] 20 25 }

  condition:
    any of them
}