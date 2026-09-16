rule TTP_XOR_QUAD_CurrentVersionRun_6299 {
  strings:
    $key_6299 = { 31 f6 [2] 15 f8 [2] 3e d4 [2] 10 f6 [2] 04 ed [2] 0b f7 [2] 15 ea [2] 17 eb [2] 0c ed [2] 10 ea [2] 0c c5 }

  condition:
    any of them
}