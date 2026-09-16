rule TTP_XOR_QUAD_CurrentVersionRun_118a {
  strings:
    $key_118a = { 42 e5 [2] 66 eb [2] 4d c7 [2] 63 e5 [2] 77 fe [2] 78 e4 [2] 66 f9 [2] 64 f8 [2] 7f fe [2] 63 f9 [2] 7f d6 }

  condition:
    any of them
}