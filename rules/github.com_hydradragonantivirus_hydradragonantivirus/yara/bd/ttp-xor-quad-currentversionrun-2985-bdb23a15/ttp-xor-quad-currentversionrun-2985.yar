rule TTP_XOR_QUAD_CurrentVersionRun_2985 {
  strings:
    $key_2985 = { 7a ea [2] 5e e4 [2] 75 c8 [2] 5b ea [2] 4f f1 [2] 40 eb [2] 5e f6 [2] 5c f7 [2] 47 f1 [2] 5b f6 [2] 47 d9 }

  condition:
    any of them
}