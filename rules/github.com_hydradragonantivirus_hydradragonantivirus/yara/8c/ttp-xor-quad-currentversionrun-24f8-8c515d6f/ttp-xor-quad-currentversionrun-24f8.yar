rule TTP_XOR_QUAD_CurrentVersionRun_24f8 {
  strings:
    $key_24f8 = { 77 97 [2] 53 99 [2] 78 b5 [2] 56 97 [2] 42 8c [2] 4d 96 [2] 53 8b [2] 51 8a [2] 4a 8c [2] 56 8b [2] 4a a4 }

  condition:
    any of them
}