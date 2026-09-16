rule TTP_XOR_QUAD_CurrentVersionRun_4684 {
  strings:
    $key_4684 = { 15 eb [2] 31 e5 [2] 1a c9 [2] 34 eb [2] 20 f0 [2] 2f ea [2] 31 f7 [2] 33 f6 [2] 28 f0 [2] 34 f7 [2] 28 d8 }

  condition:
    any of them
}