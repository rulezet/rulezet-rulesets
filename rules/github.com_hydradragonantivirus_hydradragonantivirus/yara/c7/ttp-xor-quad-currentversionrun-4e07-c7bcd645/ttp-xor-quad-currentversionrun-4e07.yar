rule TTP_XOR_QUAD_CurrentVersionRun_4e07 {
  strings:
    $key_4e07 = { 1d 68 [2] 39 66 [2] 12 4a [2] 3c 68 [2] 28 73 [2] 27 69 [2] 39 74 [2] 3b 75 [2] 20 73 [2] 3c 74 [2] 20 5b }

  condition:
    any of them
}