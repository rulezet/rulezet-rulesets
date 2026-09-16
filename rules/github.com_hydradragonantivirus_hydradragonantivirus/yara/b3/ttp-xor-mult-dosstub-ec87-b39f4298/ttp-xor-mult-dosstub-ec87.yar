rule TTP_XOR_MULT_DOSStub_ec87 {
  strings:
    $key_ec87 = { b8 ef [2] cc f7 [2] 8b f5 [2] cc e4 [2] 82 e8 [2] 8e e2 [2] 99 e9 [2] 82 a7 [2] bf }

  condition:
    any of them
}