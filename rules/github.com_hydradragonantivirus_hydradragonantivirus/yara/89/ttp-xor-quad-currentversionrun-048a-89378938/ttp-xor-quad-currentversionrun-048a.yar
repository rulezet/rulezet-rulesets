rule TTP_XOR_QUAD_CurrentVersionRun_048a {
  strings:
    $key_048a = { 57 e5 [2] 73 eb [2] 58 c7 [2] 76 e5 [2] 62 fe [2] 6d e4 [2] 73 f9 [2] 71 f8 [2] 6a fe [2] 76 f9 [2] 6a d6 }

  condition:
    any of them
}