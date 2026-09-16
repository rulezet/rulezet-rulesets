rule TTP_XOR_QUAD_CurrentVersionRun_7585 {
  strings:
    $key_7585 = { 26 ea [2] 02 e4 [2] 29 c8 [2] 07 ea [2] 13 f1 [2] 1c eb [2] 02 f6 [2] 00 f7 [2] 1b f1 [2] 07 f6 [2] 1b d9 }

  condition:
    any of them
}