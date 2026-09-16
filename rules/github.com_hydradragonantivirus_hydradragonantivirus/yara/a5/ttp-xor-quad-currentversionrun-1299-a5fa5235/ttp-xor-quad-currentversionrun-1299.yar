rule TTP_XOR_QUAD_CurrentVersionRun_1299 {
  strings:
    $key_1299 = { 41 f6 [2] 65 f8 [2] 4e d4 [2] 60 f6 [2] 74 ed [2] 7b f7 [2] 65 ea [2] 67 eb [2] 7c ed [2] 60 ea [2] 7c c5 }

  condition:
    any of them
}