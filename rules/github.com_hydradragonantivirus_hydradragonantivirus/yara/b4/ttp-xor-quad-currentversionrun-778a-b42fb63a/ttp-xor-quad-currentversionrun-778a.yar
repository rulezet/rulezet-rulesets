rule TTP_XOR_QUAD_CurrentVersionRun_778a {
  strings:
    $key_778a = { 24 e5 [2] 00 eb [2] 2b c7 [2] 05 e5 [2] 11 fe [2] 1e e4 [2] 00 f9 [2] 02 f8 [2] 19 fe [2] 05 f9 [2] 19 d6 }

  condition:
    any of them
}