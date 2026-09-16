rule TTP_XOR_QUAD_CurrentVersionRun_24e4 {
  strings:
    $key_24e4 = { 77 8b [2] 53 85 [2] 78 a9 [2] 56 8b [2] 42 90 [2] 4d 8a [2] 53 97 [2] 51 96 [2] 4a 90 [2] 56 97 [2] 4a b8 }

  condition:
    any of them
}