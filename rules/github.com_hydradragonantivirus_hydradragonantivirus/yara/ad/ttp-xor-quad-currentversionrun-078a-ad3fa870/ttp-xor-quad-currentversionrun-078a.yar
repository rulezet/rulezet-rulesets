rule TTP_XOR_QUAD_CurrentVersionRun_078a {
  strings:
    $key_078a = { 54 e5 [2] 70 eb [2] 5b c7 [2] 75 e5 [2] 61 fe [2] 6e e4 [2] 70 f9 [2] 72 f8 [2] 69 fe [2] 75 f9 [2] 69 d6 }

  condition:
    any of them
}