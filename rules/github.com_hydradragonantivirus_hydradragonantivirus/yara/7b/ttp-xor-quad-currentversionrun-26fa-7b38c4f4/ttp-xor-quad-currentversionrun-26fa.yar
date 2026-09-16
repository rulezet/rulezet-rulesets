rule TTP_XOR_QUAD_CurrentVersionRun_26fa {
  strings:
    $key_26fa = { 75 95 [2] 51 9b [2] 7a b7 [2] 54 95 [2] 40 8e [2] 4f 94 [2] 51 89 [2] 53 88 [2] 48 8e [2] 54 89 [2] 48 a6 }

  condition:
    any of them
}