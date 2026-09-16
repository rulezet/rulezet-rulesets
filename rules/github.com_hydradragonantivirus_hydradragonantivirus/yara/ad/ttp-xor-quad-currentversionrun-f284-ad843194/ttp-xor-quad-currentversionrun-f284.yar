rule TTP_XOR_QUAD_CurrentVersionRun_f284 {
  strings:
    $key_f284 = { a1 eb [2] 85 e5 [2] ae c9 [2] 80 eb [2] 94 f0 [2] 9b ea [2] 85 f7 [2] 87 f6 [2] 9c f0 [2] 80 f7 [2] 9c d8 }

  condition:
    any of them
}