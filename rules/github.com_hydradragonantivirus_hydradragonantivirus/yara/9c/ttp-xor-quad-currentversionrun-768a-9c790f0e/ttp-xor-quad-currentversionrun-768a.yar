rule TTP_XOR_QUAD_CurrentVersionRun_768a {
  strings:
    $key_768a = { 25 e5 [2] 01 eb [2] 2a c7 [2] 04 e5 [2] 10 fe [2] 1f e4 [2] 01 f9 [2] 03 f8 [2] 18 fe [2] 04 f9 [2] 18 d6 }

  condition:
    any of them
}