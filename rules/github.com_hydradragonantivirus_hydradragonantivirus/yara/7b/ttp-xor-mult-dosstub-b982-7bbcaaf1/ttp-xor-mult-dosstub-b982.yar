rule TTP_XOR_MULT_DOSStub_b982 {
  strings:
    $key_b982 = { ed ea [2] 99 f2 [2] de f0 [2] 99 e1 [2] d7 ed [2] db e7 [2] cc ec [2] d7 a2 [2] ea }

  condition:
    any of them
}