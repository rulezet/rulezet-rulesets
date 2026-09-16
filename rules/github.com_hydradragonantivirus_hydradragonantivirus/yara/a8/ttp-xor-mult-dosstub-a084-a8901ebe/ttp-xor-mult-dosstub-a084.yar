rule TTP_XOR_MULT_DOSStub_a084 {
  strings:
    $key_a084 = { f4 ec [2] 80 f4 [2] c7 f6 [2] 80 e7 [2] ce eb [2] c2 e1 [2] d5 ea [2] ce a4 [2] f3 }

  condition:
    any of them
}