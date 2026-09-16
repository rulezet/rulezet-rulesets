rule TTP_XOR_QUAD_CurrentVersionRun_0585 {
  strings:
    $key_0585 = { 56 ea [2] 72 e4 [2] 59 c8 [2] 77 ea [2] 63 f1 [2] 6c eb [2] 72 f6 [2] 70 f7 [2] 6b f1 [2] 77 f6 [2] 6b d9 }

  condition:
    any of them
}