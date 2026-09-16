rule TTP_XOR_QUAD_CurrentVersionRun_7b39 {
  strings:
    $key_7b39 = { 28 56 [2] 0c 58 [2] 27 74 [2] 09 56 [2] 1d 4d [2] 12 57 [2] 0c 4a [2] 0e 4b [2] 15 4d [2] 09 4a [2] 15 65 }

  condition:
    any of them
}