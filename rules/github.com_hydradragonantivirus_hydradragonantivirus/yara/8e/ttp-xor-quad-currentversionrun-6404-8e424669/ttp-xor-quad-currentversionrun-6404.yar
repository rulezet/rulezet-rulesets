rule TTP_XOR_QUAD_CurrentVersionRun_6404 {
  strings:
    $key_6404 = { 37 6b [2] 13 65 [2] 38 49 [2] 16 6b [2] 02 70 [2] 0d 6a [2] 13 77 [2] 11 76 [2] 0a 70 [2] 16 77 [2] 0a 58 }

  condition:
    any of them
}