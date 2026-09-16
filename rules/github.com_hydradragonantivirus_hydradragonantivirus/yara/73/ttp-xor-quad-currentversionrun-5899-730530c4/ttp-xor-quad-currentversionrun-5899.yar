rule TTP_XOR_QUAD_CurrentVersionRun_5899 {
  strings:
    $key_5899 = { 0b f6 [2] 2f f8 [2] 04 d4 [2] 2a f6 [2] 3e ed [2] 31 f7 [2] 2f ea [2] 2d eb [2] 36 ed [2] 2a ea [2] 36 c5 }

  condition:
    any of them
}