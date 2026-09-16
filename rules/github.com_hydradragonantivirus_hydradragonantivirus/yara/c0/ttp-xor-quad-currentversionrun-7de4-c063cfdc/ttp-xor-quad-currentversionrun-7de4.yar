rule TTP_XOR_QUAD_CurrentVersionRun_7de4 {
  strings:
    $key_7de4 = { 2e 8b [2] 0a 85 [2] 21 a9 [2] 0f 8b [2] 1b 90 [2] 14 8a [2] 0a 97 [2] 08 96 [2] 13 90 [2] 0f 97 [2] 13 b8 }

  condition:
    any of them
}