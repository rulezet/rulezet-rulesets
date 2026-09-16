rule TTP_XOR_QUAD_CurrentVersionRun_f28a {
  strings:
    $key_f28a = { a1 e5 [2] 85 eb [2] ae c7 [2] 80 e5 [2] 94 fe [2] 9b e4 [2] 85 f9 [2] 87 f8 [2] 9c fe [2] 80 f9 [2] 9c d6 }

  condition:
    any of them
}