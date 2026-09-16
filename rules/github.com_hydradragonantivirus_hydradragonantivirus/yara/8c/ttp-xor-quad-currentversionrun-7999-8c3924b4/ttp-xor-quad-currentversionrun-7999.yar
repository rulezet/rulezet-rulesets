rule TTP_XOR_QUAD_CurrentVersionRun_7999 {
  strings:
    $key_7999 = { 2a f6 [2] 0e f8 [2] 25 d4 [2] 0b f6 [2] 1f ed [2] 10 f7 [2] 0e ea [2] 0c eb [2] 17 ed [2] 0b ea [2] 17 c5 }

  condition:
    any of them
}