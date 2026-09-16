rule TTP_XOR_QUAD_CurrentVersionRun_1999 {
  strings:
    $key_1999 = { 4a f6 [2] 6e f8 [2] 45 d4 [2] 6b f6 [2] 7f ed [2] 70 f7 [2] 6e ea [2] 6c eb [2] 77 ed [2] 6b ea [2] 77 c5 }

  condition:
    any of them
}