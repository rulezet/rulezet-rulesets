rule TTP_XOR_QUAD_CurrentVersionRun_5525 {
  strings:
    $key_5525 = { 06 4a [2] 22 44 [2] 09 68 [2] 27 4a [2] 33 51 [2] 3c 4b [2] 22 56 [2] 20 57 [2] 3b 51 [2] 27 56 [2] 3b 79 }

  condition:
    any of them
}