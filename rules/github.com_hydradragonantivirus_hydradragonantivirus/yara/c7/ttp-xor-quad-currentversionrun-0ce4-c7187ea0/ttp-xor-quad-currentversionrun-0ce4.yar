rule TTP_XOR_QUAD_CurrentVersionRun_0ce4 {
  strings:
    $key_0ce4 = { 5f 8b [2] 7b 85 [2] 50 a9 [2] 7e 8b [2] 6a 90 [2] 65 8a [2] 7b 97 [2] 79 96 [2] 62 90 [2] 7e 97 [2] 62 b8 }

  condition:
    any of them
}