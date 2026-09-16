rule TTP_XOR_QUAD_CurrentVersionRun_518a {
  strings:
    $key_518a = { 02 e5 [2] 26 eb [2] 0d c7 [2] 23 e5 [2] 37 fe [2] 38 e4 [2] 26 f9 [2] 24 f8 [2] 3f fe [2] 23 f9 [2] 3f d6 }

  condition:
    any of them
}