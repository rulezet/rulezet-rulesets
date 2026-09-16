rule TTP_XOR_QUAD_CurrentVersionRun_64f9 {
  strings:
    $key_64f9 = { 37 96 [2] 13 98 [2] 38 b4 [2] 16 96 [2] 02 8d [2] 0d 97 [2] 13 8a [2] 11 8b [2] 0a 8d [2] 16 8a [2] 0a a5 }

  condition:
    any of them
}