rule TTP_XOR_QUAD_CurrentVersionRun_46fa {
  strings:
    $key_46fa = { 15 95 [2] 31 9b [2] 1a b7 [2] 34 95 [2] 20 8e [2] 2f 94 [2] 31 89 [2] 33 88 [2] 28 8e [2] 34 89 [2] 28 a6 }

  condition:
    any of them
}