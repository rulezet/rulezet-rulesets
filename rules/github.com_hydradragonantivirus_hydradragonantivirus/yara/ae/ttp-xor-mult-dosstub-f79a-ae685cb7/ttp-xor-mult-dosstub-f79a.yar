rule TTP_XOR_MULT_DOSStub_f79a {
  strings:
    $key_f79a = { a3 f2 [2] d7 ea [2] 90 e8 [2] d7 f9 [2] 99 f5 [2] 95 ff [2] 82 f4 [2] 99 ba [2] a4 }

  condition:
    any of them
}