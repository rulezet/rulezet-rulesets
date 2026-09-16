rule TTP_XOR_QUAD_CurrentVersionRun_6304 {
  strings:
    $key_6304 = { 30 6b [2] 14 65 [2] 3f 49 [2] 11 6b [2] 05 70 [2] 0a 6a [2] 14 77 [2] 16 76 [2] 0d 70 [2] 11 77 [2] 0d 58 }

  condition:
    any of them
}