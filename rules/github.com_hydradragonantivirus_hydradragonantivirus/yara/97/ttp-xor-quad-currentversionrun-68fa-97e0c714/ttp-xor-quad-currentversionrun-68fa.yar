rule TTP_XOR_QUAD_CurrentVersionRun_68fa {
  strings:
    $key_68fa = { 3b 95 [2] 1f 9b [2] 34 b7 [2] 1a 95 [2] 0e 8e [2] 01 94 [2] 1f 89 [2] 1d 88 [2] 06 8e [2] 1a 89 [2] 06 a6 }

  condition:
    any of them
}