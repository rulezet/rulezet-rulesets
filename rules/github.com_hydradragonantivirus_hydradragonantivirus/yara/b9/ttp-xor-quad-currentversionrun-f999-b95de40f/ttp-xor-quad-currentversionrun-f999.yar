rule TTP_XOR_QUAD_CurrentVersionRun_f999 {
  strings:
    $key_f999 = { aa f6 [2] 8e f8 [2] a5 d4 [2] 8b f6 [2] 9f ed [2] 90 f7 [2] 8e ea [2] 8c eb [2] 97 ed [2] 8b ea [2] 97 c5 }

  condition:
    any of them
}