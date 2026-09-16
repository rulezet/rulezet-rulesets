rule TTP_XOR_QUAD_CurrentVersionRun_6479 {
  strings:
    $key_6479 = { 37 16 [2] 13 18 [2] 38 34 [2] 16 16 [2] 02 0d [2] 0d 17 [2] 13 0a [2] 11 0b [2] 0a 0d [2] 16 0a [2] 0a 25 }

  condition:
    any of them
}