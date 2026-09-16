rule TTP_XOR_QUAD_CurrentVersionRun_2ae4 {
  strings:
    $key_2ae4 = { 79 8b [2] 5d 85 [2] 76 a9 [2] 58 8b [2] 4c 90 [2] 43 8a [2] 5d 97 [2] 5f 96 [2] 44 90 [2] 58 97 [2] 44 b8 }

  condition:
    any of them
}