rule TTP_XOR_QUAD_CurrentVersionRun_2fe4 {
  strings:
    $key_2fe4 = { 7c 8b [2] 58 85 [2] 73 a9 [2] 5d 8b [2] 49 90 [2] 46 8a [2] 58 97 [2] 5a 96 [2] 41 90 [2] 5d 97 [2] 41 b8 }

  condition:
    any of them
}