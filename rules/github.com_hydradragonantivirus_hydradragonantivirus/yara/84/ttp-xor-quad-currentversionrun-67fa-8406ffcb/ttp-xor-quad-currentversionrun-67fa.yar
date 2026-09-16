rule TTP_XOR_QUAD_CurrentVersionRun_67fa {
  strings:
    $key_67fa = { 34 95 [2] 10 9b [2] 3b b7 [2] 15 95 [2] 01 8e [2] 0e 94 [2] 10 89 [2] 12 88 [2] 09 8e [2] 15 89 [2] 09 a6 }

  condition:
    any of them
}