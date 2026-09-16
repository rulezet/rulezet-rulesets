rule TTP_XOR_QUAD_CurrentVersionRun_7899 {
  strings:
    $key_7899 = { 2b f6 [2] 0f f8 [2] 24 d4 [2] 0a f6 [2] 1e ed [2] 11 f7 [2] 0f ea [2] 0d eb [2] 16 ed [2] 0a ea [2] 16 c5 }

  condition:
    any of them
}