rule TTP_XOR_QUAD_CurrentVersionRun_6999 {
  strings:
    $key_6999 = { 3a f6 [2] 1e f8 [2] 35 d4 [2] 1b f6 [2] 0f ed [2] 00 f7 [2] 1e ea [2] 1c eb [2] 07 ed [2] 1b ea [2] 07 c5 }

  condition:
    any of them
}