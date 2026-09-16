rule TTP_XOR_QUAD_CurrentVersionRun_668a {
  strings:
    $key_668a = { 35 e5 [2] 11 eb [2] 3a c7 [2] 14 e5 [2] 00 fe [2] 0f e4 [2] 11 f9 [2] 13 f8 [2] 08 fe [2] 14 f9 [2] 08 d6 }

  condition:
    any of them
}