rule TTP_XOR_QUAD_CurrentVersionRun_60fa {
  strings:
    $key_60fa = { 33 95 [2] 17 9b [2] 3c b7 [2] 12 95 [2] 06 8e [2] 09 94 [2] 17 89 [2] 15 88 [2] 0e 8e [2] 12 89 [2] 0e a6 }

  condition:
    any of them
}