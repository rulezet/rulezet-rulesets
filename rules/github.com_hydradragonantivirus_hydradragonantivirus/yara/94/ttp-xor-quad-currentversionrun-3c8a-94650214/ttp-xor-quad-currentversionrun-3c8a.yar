rule TTP_XOR_QUAD_CurrentVersionRun_3c8a {
  strings:
    $key_3c8a = { 6f e5 [2] 4b eb [2] 60 c7 [2] 4e e5 [2] 5a fe [2] 55 e4 [2] 4b f9 [2] 49 f8 [2] 52 fe [2] 4e f9 [2] 52 d6 }

  condition:
    any of them
}