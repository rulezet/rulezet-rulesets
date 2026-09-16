rule TTP_XOR_MULT_DOSStub_f291 {
  strings:
    $key_f291 = { a6 f9 [2] d2 e1 [2] 95 e3 [2] d2 f2 [2] 9c fe [2] 90 f4 [2] 87 ff [2] 9c b1 [2] a1 }

  condition:
    any of them
}