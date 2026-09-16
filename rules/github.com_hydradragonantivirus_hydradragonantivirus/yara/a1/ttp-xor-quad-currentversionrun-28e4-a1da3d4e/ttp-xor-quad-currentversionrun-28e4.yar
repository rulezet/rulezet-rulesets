rule TTP_XOR_QUAD_CurrentVersionRun_28e4 {
  strings:
    $key_28e4 = { 7b 8b [2] 5f 85 [2] 74 a9 [2] 5a 8b [2] 4e 90 [2] 41 8a [2] 5f 97 [2] 5d 96 [2] 46 90 [2] 5a 97 [2] 46 b8 }

  condition:
    any of them
}