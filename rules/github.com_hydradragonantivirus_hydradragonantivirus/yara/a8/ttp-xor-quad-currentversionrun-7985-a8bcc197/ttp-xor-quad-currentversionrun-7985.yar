rule TTP_XOR_QUAD_CurrentVersionRun_7985 {
  strings:
    $key_7985 = { 2a ea [2] 0e e4 [2] 25 c8 [2] 0b ea [2] 1f f1 [2] 10 eb [2] 0e f6 [2] 0c f7 [2] 17 f1 [2] 0b f6 [2] 17 d9 }

  condition:
    any of them
}