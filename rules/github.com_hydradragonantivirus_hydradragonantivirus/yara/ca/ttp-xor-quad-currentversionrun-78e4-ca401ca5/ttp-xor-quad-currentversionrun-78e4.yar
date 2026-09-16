rule TTP_XOR_QUAD_CurrentVersionRun_78e4 {
  strings:
    $key_78e4 = { 2b 8b [2] 0f 85 [2] 24 a9 [2] 0a 8b [2] 1e 90 [2] 11 8a [2] 0f 97 [2] 0d 96 [2] 16 90 [2] 0a 97 [2] 16 b8 }

  condition:
    any of them
}