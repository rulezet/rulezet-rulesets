rule TTP_XOR_QUAD_CurrentVersionRun_24f9 {
  strings:
    $key_24f9 = { 77 96 [2] 53 98 [2] 78 b4 [2] 56 96 [2] 42 8d [2] 4d 97 [2] 53 8a [2] 51 8b [2] 4a 8d [2] 56 8a [2] 4a a5 }

  condition:
    any of them
}