rule TTP_XOR_QUAD_CurrentVersionRun_3899 {
  strings:
    $key_3899 = { 6b f6 [2] 4f f8 [2] 64 d4 [2] 4a f6 [2] 5e ed [2] 51 f7 [2] 4f ea [2] 4d eb [2] 56 ed [2] 4a ea [2] 56 c5 }

  condition:
    any of them
}