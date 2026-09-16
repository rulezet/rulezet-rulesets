rule TTP_XOR_QUAD_CurrentVersionRun_4ce4 {
  strings:
    $key_4ce4 = { 1f 8b [2] 3b 85 [2] 10 a9 [2] 3e 8b [2] 2a 90 [2] 25 8a [2] 3b 97 [2] 39 96 [2] 22 90 [2] 3e 97 [2] 22 b8 }

  condition:
    any of them
}