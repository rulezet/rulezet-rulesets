rule TTP_XOR_QUAD_CurrentVersionRun_6448 {
  strings:
    $key_6448 = { 37 27 [2] 13 29 [2] 38 05 [2] 16 27 [2] 02 3c [2] 0d 26 [2] 13 3b [2] 11 3a [2] 0a 3c [2] 16 3b [2] 0a 14 }

  condition:
    any of them
}