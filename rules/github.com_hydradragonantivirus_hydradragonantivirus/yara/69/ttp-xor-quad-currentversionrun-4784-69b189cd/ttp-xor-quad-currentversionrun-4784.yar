rule TTP_XOR_QUAD_CurrentVersionRun_4784 {
  strings:
    $key_4784 = { 14 eb [2] 30 e5 [2] 1b c9 [2] 35 eb [2] 21 f0 [2] 2e ea [2] 30 f7 [2] 32 f6 [2] 29 f0 [2] 35 f7 [2] 29 d8 }

  condition:
    any of them
}