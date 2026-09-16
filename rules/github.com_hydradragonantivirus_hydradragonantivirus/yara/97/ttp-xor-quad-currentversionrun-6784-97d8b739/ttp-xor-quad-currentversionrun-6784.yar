rule TTP_XOR_QUAD_CurrentVersionRun_6784 {
  strings:
    $key_6784 = { 34 eb [2] 10 e5 [2] 3b c9 [2] 15 eb [2] 01 f0 [2] 0e ea [2] 10 f7 [2] 12 f6 [2] 09 f0 [2] 15 f7 [2] 09 d8 }

  condition:
    any of them
}