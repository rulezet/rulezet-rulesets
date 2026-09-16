rule TTP_XOR_QUAD_CurrentVersionRun_5139 {
  strings:
    $key_5139 = { 02 56 [2] 26 58 [2] 0d 74 [2] 23 56 [2] 37 4d [2] 38 57 [2] 26 4a [2] 24 4b [2] 3f 4d [2] 23 4a [2] 3f 65 }

  condition:
    any of them
}