rule TTP_XOR_QUAD_CurrentVersionRun_6015 {
  strings:
    $key_6015 = { 33 7a [2] 17 74 [2] 3c 58 [2] 12 7a [2] 06 61 [2] 09 7b [2] 17 66 [2] 15 67 [2] 0e 61 [2] 12 66 [2] 0e 49 }

  condition:
    any of them
}