rule TTP_XOR_QUAD_CurrentVersionRun_4e25 {
  strings:
    $key_4e25 = { 1d 4a [2] 39 44 [2] 12 68 [2] 3c 4a [2] 28 51 [2] 27 4b [2] 39 56 [2] 3b 57 [2] 20 51 [2] 3c 56 [2] 20 79 }

  condition:
    any of them
}