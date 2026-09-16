rule TTP_XOR_QUAD_CurrentVersionRun_e899 {
  strings:
    $key_e899 = { bb f6 [2] 9f f8 [2] b4 d4 [2] 9a f6 [2] 8e ed [2] 81 f7 [2] 9f ea [2] 9d eb [2] 86 ed [2] 9a ea [2] 86 c5 }

  condition:
    any of them
}