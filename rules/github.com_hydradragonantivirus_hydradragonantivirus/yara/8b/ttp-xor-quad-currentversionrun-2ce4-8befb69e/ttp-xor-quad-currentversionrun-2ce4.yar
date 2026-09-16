rule TTP_XOR_QUAD_CurrentVersionRun_2ce4 {
  strings:
    $key_2ce4 = { 7f 8b [2] 5b 85 [2] 70 a9 [2] 5e 8b [2] 4a 90 [2] 45 8a [2] 5b 97 [2] 59 96 [2] 42 90 [2] 5e 97 [2] 42 b8 }

  condition:
    any of them
}