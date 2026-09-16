rule TTP_XOR_QUAD_CurrentVersionRun_5104 {
  strings:
    $key_5104 = { 02 6b [2] 26 65 [2] 0d 49 [2] 23 6b [2] 37 70 [2] 38 6a [2] 26 77 [2] 24 76 [2] 3f 70 [2] 23 77 [2] 3f 58 }

  condition:
    any of them
}