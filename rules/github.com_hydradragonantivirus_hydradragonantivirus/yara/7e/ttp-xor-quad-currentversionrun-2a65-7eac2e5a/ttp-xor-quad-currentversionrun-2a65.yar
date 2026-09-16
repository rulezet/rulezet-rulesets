rule TTP_XOR_QUAD_CurrentVersionRun_2a65 {
  strings:
    $key_2a65 = { 79 0a [2] 5d 04 [2] 76 28 [2] 58 0a [2] 4c 11 [2] 43 0b [2] 5d 16 [2] 5f 17 [2] 44 11 [2] 58 16 [2] 44 39 }

  condition:
    any of them
}