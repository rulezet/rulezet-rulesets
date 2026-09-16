rule TTP_XOR_MULT_DOSStub_ec86 {
  strings:
    $key_ec86 = { b8 ee [2] cc f6 [2] 8b f4 [2] cc e5 [2] 82 e9 [2] 8e e3 [2] 99 e8 [2] 82 a6 [2] bf }

  condition:
    any of them
}