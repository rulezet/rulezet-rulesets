rule TTP_XOR_QUAD_CurrentVersionRun_3679 {
  strings:
    $key_3679 = { 65 16 [2] 41 18 [2] 6a 34 [2] 44 16 [2] 50 0d [2] 5f 17 [2] 41 0a [2] 43 0b [2] 58 0d [2] 44 0a [2] 58 25 }

  condition:
    any of them
}