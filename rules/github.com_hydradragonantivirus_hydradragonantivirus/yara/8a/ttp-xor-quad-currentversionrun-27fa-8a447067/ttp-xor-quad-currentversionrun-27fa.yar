rule TTP_XOR_QUAD_CurrentVersionRun_27fa {
  strings:
    $key_27fa = { 74 95 [2] 50 9b [2] 7b b7 [2] 55 95 [2] 41 8e [2] 4e 94 [2] 50 89 [2] 52 88 [2] 49 8e [2] 55 89 [2] 49 a6 }

  condition:
    any of them
}