rule TTP_XOR_QUAD_CurrentVersionRun_528a {
  strings:
    $key_528a = { 01 e5 [2] 25 eb [2] 0e c7 [2] 20 e5 [2] 34 fe [2] 3b e4 [2] 25 f9 [2] 27 f8 [2] 3c fe [2] 20 f9 [2] 3c d6 }

  condition:
    any of them
}