rule TTP_XOR_QUAD_CurrentVersionRun_24fa {
  strings:
    $key_24fa = { 77 95 [2] 53 9b [2] 78 b7 [2] 56 95 [2] 42 8e [2] 4d 94 [2] 53 89 [2] 51 88 [2] 4a 8e [2] 56 89 [2] 4a a6 }

  condition:
    any of them
}