rule TTP_XOR_MULT_DOSStub_ec80 {
  strings:
    $key_ec80 = { b8 e8 [2] cc f0 [2] 8b f2 [2] cc e3 [2] 82 ef [2] 8e e5 [2] 99 ee [2] 82 a0 [2] bf }

  condition:
    any of them
}