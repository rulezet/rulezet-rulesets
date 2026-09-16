rule TTP_XOR_QUAD_CurrentVersionRun_018a {
  strings:
    $key_018a = { 52 e5 [2] 76 eb [2] 5d c7 [2] 73 e5 [2] 67 fe [2] 68 e4 [2] 76 f9 [2] 74 f8 [2] 6f fe [2] 73 f9 [2] 6f d6 }

  condition:
    any of them
}