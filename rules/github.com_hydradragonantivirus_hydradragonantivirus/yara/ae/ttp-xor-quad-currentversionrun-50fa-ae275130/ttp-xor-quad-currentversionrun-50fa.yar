rule TTP_XOR_QUAD_CurrentVersionRun_50fa {
  strings:
    $key_50fa = { 03 95 [2] 27 9b [2] 0c b7 [2] 22 95 [2] 36 8e [2] 39 94 [2] 27 89 [2] 25 88 [2] 3e 8e [2] 22 89 [2] 3e a6 }

  condition:
    any of them
}