rule TTP_XOR_QUAD_CurrentVersionRun_648a {
  strings:
    $key_648a = { 37 e5 [2] 13 eb [2] 38 c7 [2] 16 e5 [2] 02 fe [2] 0d e4 [2] 13 f9 [2] 11 f8 [2] 0a fe [2] 16 f9 [2] 0a d6 }

  condition:
    any of them
}