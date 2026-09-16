rule TTP_XOR_QUAD_CurrentVersionRun_4098 {
  strings:
    $key_4098 = { 13 f7 [2] 37 f9 [2] 1c d5 [2] 32 f7 [2] 26 ec [2] 29 f6 [2] 37 eb [2] 35 ea [2] 2e ec [2] 32 eb [2] 2e c4 }

  condition:
    any of them
}