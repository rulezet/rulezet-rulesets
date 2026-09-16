rule TTP_XOR_MULT_DOSStub_48d5 {
  strings:
    $key_48d5 = { 1c bd [2] 68 a5 [2] 2f a7 [2] 68 b6 [2] 26 ba [2] 2a b0 [2] 3d bb [2] 26 f5 [2] 1b }

  condition:
    any of them
}