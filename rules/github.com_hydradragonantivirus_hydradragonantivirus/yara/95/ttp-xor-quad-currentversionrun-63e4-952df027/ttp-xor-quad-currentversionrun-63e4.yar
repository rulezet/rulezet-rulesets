rule TTP_XOR_QUAD_CurrentVersionRun_63e4 {
  strings:
    $key_63e4 = { 30 8b [2] 14 85 [2] 3f a9 [2] 11 8b [2] 05 90 [2] 0a 8a [2] 14 97 [2] 16 96 [2] 0d 90 [2] 11 97 [2] 0d b8 }

  condition:
    any of them
}