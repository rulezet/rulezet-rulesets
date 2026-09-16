rule TTP_XOR_MULT_DOSStub_0783 {
  strings:
    $key_0783 = { 53 eb [2] 27 f3 [2] 60 f1 [2] 27 e0 [2] 69 ec [2] 65 e6 [2] 72 ed [2] 69 a3 [2] 54 }

  condition:
    any of them
}