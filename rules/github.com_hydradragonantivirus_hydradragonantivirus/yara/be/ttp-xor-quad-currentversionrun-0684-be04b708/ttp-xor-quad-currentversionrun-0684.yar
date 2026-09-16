rule TTP_XOR_QUAD_CurrentVersionRun_0684 {
  strings:
    $key_0684 = { 55 eb [2] 71 e5 [2] 5a c9 [2] 74 eb [2] 60 f0 [2] 6f ea [2] 71 f7 [2] 73 f6 [2] 68 f0 [2] 74 f7 [2] 68 d8 }

  condition:
    any of them
}