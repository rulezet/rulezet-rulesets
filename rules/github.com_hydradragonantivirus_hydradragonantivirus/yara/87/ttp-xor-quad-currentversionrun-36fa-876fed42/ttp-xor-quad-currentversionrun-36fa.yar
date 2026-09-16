rule TTP_XOR_QUAD_CurrentVersionRun_36fa {
  strings:
    $key_36fa = { 65 95 [2] 41 9b [2] 6a b7 [2] 44 95 [2] 50 8e [2] 5f 94 [2] 41 89 [2] 43 88 [2] 58 8e [2] 44 89 [2] 58 a6 }

  condition:
    any of them
}