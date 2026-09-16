rule TTP_XOR_QUAD_CurrentVersionRun_07fa {
  strings:
    $key_07fa = { 54 95 [2] 70 9b [2] 5b b7 [2] 75 95 [2] 61 8e [2] 6e 94 [2] 70 89 [2] 72 88 [2] 69 8e [2] 75 89 [2] 69 a6 }

  condition:
    any of them
}