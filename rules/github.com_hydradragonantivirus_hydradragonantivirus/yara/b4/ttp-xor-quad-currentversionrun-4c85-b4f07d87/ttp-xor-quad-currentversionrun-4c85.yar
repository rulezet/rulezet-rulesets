rule TTP_XOR_QUAD_CurrentVersionRun_4c85 {
  strings:
    $key_4c85 = { 1f ea [2] 3b e4 [2] 10 c8 [2] 3e ea [2] 2a f1 [2] 25 eb [2] 3b f6 [2] 39 f7 [2] 22 f1 [2] 3e f6 [2] 22 d9 }

  condition:
    any of them
}