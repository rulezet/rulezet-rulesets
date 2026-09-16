rule TTP_XOR_QUAD_CurrentVersionRun_7c99 {
  strings:
    $key_7c99 = { 2f f6 [2] 0b f8 [2] 20 d4 [2] 0e f6 [2] 1a ed [2] 15 f7 [2] 0b ea [2] 09 eb [2] 12 ed [2] 0e ea [2] 12 c5 }

  condition:
    any of them
}