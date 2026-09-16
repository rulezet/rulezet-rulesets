rule TTP_XOR_MULT_DOSStub_b987 {
  strings:
    $key_b987 = { ed ef [2] 99 f7 [2] de f5 [2] 99 e4 [2] d7 e8 [2] db e2 [2] cc e9 [2] d7 a7 [2] ea }

  condition:
    any of them
}