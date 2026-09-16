rule TTP_XOR_MULT_DOSStub_3d82 {
  strings:
    $key_3d82 = { 69 ea [2] 1d f2 [2] 5a f0 [2] 1d e1 [2] 53 ed [2] 5f e7 [2] 48 ec [2] 53 a2 [2] 6e }

  condition:
    any of them
}