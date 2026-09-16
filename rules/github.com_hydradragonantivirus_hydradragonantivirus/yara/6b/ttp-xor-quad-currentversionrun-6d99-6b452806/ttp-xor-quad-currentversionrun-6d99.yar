rule TTP_XOR_QUAD_CurrentVersionRun_6d99 {
  strings:
    $key_6d99 = { 3e f6 [2] 1a f8 [2] 31 d4 [2] 1f f6 [2] 0b ed [2] 04 f7 [2] 1a ea [2] 18 eb [2] 03 ed [2] 1f ea [2] 03 c5 }

  condition:
    any of them
}