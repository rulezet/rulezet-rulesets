rule TTP_XOR_QUAD_CurrentVersionRun_4c99 {
  strings:
    $key_4c99 = { 1f f6 [2] 3b f8 [2] 10 d4 [2] 3e f6 [2] 2a ed [2] 25 f7 [2] 3b ea [2] 39 eb [2] 22 ed [2] 3e ea [2] 22 c5 }

  condition:
    any of them
}