rule TTP_XOR_QUAD_CurrentVersionRun_7299 {
  strings:
    $key_7299 = { 21 f6 [2] 05 f8 [2] 2e d4 [2] 00 f6 [2] 14 ed [2] 1b f7 [2] 05 ea [2] 07 eb [2] 1c ed [2] 00 ea [2] 1c c5 }

  condition:
    any of them
}