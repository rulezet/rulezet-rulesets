rule TTP_XOR_QUAD_CurrentVersionRun_55e4 {
  strings:
    $key_55e4 = { 06 8b [2] 22 85 [2] 09 a9 [2] 27 8b [2] 33 90 [2] 3c 8a [2] 22 97 [2] 20 96 [2] 3b 90 [2] 27 97 [2] 3b b8 }

  condition:
    any of them
}