rule TTP_XOR_QUAD_CurrentVersionRun_208b {
  strings:
    $key_208b = { 73 e4 [2] 57 ea [2] 7c c6 [2] 52 e4 [2] 46 ff [2] 49 e5 [2] 57 f8 [2] 55 f9 [2] 4e ff [2] 52 f8 [2] 4e d7 }

  condition:
    any of them
}