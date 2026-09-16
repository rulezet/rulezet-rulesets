rule TTP_XOR_QUAD_CurrentVersionRun_49e4 {
  strings:
    $key_49e4 = { 1a 8b [2] 3e 85 [2] 15 a9 [2] 3b 8b [2] 2f 90 [2] 20 8a [2] 3e 97 [2] 3c 96 [2] 27 90 [2] 3b 97 [2] 27 b8 }

  condition:
    any of them
}