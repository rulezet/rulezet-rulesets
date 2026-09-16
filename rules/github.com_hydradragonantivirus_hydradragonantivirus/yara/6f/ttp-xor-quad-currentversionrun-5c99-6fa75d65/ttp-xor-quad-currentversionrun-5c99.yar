rule TTP_XOR_QUAD_CurrentVersionRun_5c99 {
  strings:
    $key_5c99 = { 0f f6 [2] 2b f8 [2] 00 d4 [2] 2e f6 [2] 3a ed [2] 35 f7 [2] 2b ea [2] 29 eb [2] 32 ed [2] 2e ea [2] 32 c5 }

  condition:
    any of them
}