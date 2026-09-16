rule TTP_XOR_QUAD_CurrentVersionRun_78fa {
  strings:
    $key_78fa = { 2b 95 [2] 0f 9b [2] 24 b7 [2] 0a 95 [2] 1e 8e [2] 11 94 [2] 0f 89 [2] 0d 88 [2] 16 8e [2] 0a 89 [2] 16 a6 }

  condition:
    any of them
}