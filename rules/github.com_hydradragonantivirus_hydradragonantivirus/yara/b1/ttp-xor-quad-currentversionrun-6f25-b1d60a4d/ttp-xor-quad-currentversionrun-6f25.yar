rule TTP_XOR_QUAD_CurrentVersionRun_6f25 {
  strings:
    $key_6f25 = { 3c 4a [2] 18 44 [2] 33 68 [2] 1d 4a [2] 09 51 [2] 06 4b [2] 18 56 [2] 1a 57 [2] 01 51 [2] 1d 56 [2] 01 79 }

  condition:
    any of them
}