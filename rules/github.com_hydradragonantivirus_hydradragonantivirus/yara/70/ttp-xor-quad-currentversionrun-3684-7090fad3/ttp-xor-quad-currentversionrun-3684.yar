rule TTP_XOR_QUAD_CurrentVersionRun_3684 {
  strings:
    $key_3684 = { 65 eb [2] 41 e5 [2] 6a c9 [2] 44 eb [2] 50 f0 [2] 5f ea [2] 41 f7 [2] 43 f6 [2] 58 f0 [2] 44 f7 [2] 58 d8 }

  condition:
    any of them
}