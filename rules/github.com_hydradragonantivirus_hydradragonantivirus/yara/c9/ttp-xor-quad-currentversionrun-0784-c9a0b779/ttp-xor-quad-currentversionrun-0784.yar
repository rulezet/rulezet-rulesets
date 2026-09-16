rule TTP_XOR_QUAD_CurrentVersionRun_0784 {
  strings:
    $key_0784 = { 54 eb [2] 70 e5 [2] 5b c9 [2] 75 eb [2] 61 f0 [2] 6e ea [2] 70 f7 [2] 72 f6 [2] 69 f0 [2] 75 f7 [2] 69 d8 }

  condition:
    any of them
}