rule TTP_XOR_QUAD_CurrentVersionRun_318a {
  strings:
    $key_318a = { 62 e5 [2] 46 eb [2] 6d c7 [2] 43 e5 [2] 57 fe [2] 58 e4 [2] 46 f9 [2] 44 f8 [2] 5f fe [2] 43 f9 [2] 5f d6 }

  condition:
    any of them
}