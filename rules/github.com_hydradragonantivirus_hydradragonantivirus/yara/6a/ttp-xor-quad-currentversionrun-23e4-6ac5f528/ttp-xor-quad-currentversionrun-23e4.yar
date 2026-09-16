rule TTP_XOR_QUAD_CurrentVersionRun_23e4 {
  strings:
    $key_23e4 = { 70 8b [2] 54 85 [2] 7f a9 [2] 51 8b [2] 45 90 [2] 4a 8a [2] 54 97 [2] 56 96 [2] 4d 90 [2] 51 97 [2] 4d b8 }

  condition:
    any of them
}