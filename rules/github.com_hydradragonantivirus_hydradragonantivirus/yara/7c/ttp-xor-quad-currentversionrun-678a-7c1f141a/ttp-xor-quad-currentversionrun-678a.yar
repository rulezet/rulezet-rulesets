rule TTP_XOR_QUAD_CurrentVersionRun_678a {
  strings:
    $key_678a = { 34 e5 [2] 10 eb [2] 3b c7 [2] 15 e5 [2] 01 fe [2] 0e e4 [2] 10 f9 [2] 12 f8 [2] 09 fe [2] 15 f9 [2] 09 d6 }

  condition:
    any of them
}