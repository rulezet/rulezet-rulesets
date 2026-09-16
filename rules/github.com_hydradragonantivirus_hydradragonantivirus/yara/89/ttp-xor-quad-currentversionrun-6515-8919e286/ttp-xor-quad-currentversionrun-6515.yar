rule TTP_XOR_QUAD_CurrentVersionRun_6515 {
  strings:
    $key_6515 = { 36 7a [2] 12 74 [2] 39 58 [2] 17 7a [2] 03 61 [2] 0c 7b [2] 12 66 [2] 10 67 [2] 0b 61 [2] 17 66 [2] 0b 49 }

  condition:
    any of them
}