rule TTP_XOR_QUAD_CurrentVersionRun_0098 {
  strings:
    $key_0098 = { 53 f7 [2] 77 f9 [2] 5c d5 [2] 72 f7 [2] 66 ec [2] 69 f6 [2] 77 eb [2] 75 ea [2] 6e ec [2] 72 eb [2] 6e c4 }

  condition:
    any of them
}