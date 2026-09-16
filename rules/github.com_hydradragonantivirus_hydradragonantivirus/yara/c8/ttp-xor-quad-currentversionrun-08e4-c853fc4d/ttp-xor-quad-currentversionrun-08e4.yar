rule TTP_XOR_QUAD_CurrentVersionRun_08e4 {
  strings:
    $key_08e4 = { 5b 8b [2] 7f 85 [2] 54 a9 [2] 7a 8b [2] 6e 90 [2] 61 8a [2] 7f 97 [2] 7d 96 [2] 66 90 [2] 7a 97 [2] 66 b8 }

  condition:
    any of them
}