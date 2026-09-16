rule TTP_XOR_QUAD_CurrentVersionRun_64fa {
  strings:
    $key_64fa = { 37 95 [2] 13 9b [2] 38 b7 [2] 16 95 [2] 02 8e [2] 0d 94 [2] 13 89 [2] 11 88 [2] 0a 8e [2] 16 89 [2] 0a a6 }

  condition:
    any of them
}