rule TTP_XOR_QUAD_CurrentVersionRun_e78a {
  strings:
    $key_e78a = { b4 e5 [2] 90 eb [2] bb c7 [2] 95 e5 [2] 81 fe [2] 8e e4 [2] 90 f9 [2] 92 f8 [2] 89 fe [2] 95 f9 [2] 89 d6 }

  condition:
    any of them
}