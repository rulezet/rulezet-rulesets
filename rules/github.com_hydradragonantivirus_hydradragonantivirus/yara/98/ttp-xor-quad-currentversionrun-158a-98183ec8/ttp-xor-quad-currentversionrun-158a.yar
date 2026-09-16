rule TTP_XOR_QUAD_CurrentVersionRun_158a {
  strings:
    $key_158a = { 46 e5 [2] 62 eb [2] 49 c7 [2] 67 e5 [2] 73 fe [2] 7c e4 [2] 62 f9 [2] 60 f8 [2] 7b fe [2] 67 f9 [2] 7b d6 }

  condition:
    any of them
}