rule TTP_XOR_MULT_DOSStub_b998 {
  strings:
    $key_b998 = { ed f0 [2] 99 e8 [2] de ea [2] 99 fb [2] d7 f7 [2] db fd [2] cc f6 [2] d7 b8 [2] ea }

  condition:
    any of them
}