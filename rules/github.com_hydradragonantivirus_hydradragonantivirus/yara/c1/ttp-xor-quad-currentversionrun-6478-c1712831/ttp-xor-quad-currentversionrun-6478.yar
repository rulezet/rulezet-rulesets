rule TTP_XOR_QUAD_CurrentVersionRun_6478 {
  strings:
    $key_6478 = { 37 17 [2] 13 19 [2] 38 35 [2] 16 17 [2] 02 0c [2] 0d 16 [2] 13 0b [2] 11 0a [2] 0a 0c [2] 16 0b [2] 0a 24 }

  condition:
    any of them
}