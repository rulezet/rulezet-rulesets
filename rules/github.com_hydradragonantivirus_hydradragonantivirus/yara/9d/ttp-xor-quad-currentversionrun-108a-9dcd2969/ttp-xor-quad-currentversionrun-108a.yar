rule TTP_XOR_QUAD_CurrentVersionRun_108a {
  strings:
    $key_108a = { 43 e5 [2] 67 eb [2] 4c c7 [2] 62 e5 [2] 76 fe [2] 79 e4 [2] 67 f9 [2] 65 f8 [2] 7e fe [2] 62 f9 [2] 7e d6 }

  condition:
    any of them
}