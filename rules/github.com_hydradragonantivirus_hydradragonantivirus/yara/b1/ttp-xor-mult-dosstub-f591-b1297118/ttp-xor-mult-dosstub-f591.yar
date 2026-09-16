rule TTP_XOR_MULT_DOSStub_f591 {
  strings:
    $key_f591 = { a1 f9 [2] d5 e1 [2] 92 e3 [2] d5 f2 [2] 9b fe [2] 97 f4 [2] 80 ff [2] 9b b1 [2] a6 }

  condition:
    any of them
}