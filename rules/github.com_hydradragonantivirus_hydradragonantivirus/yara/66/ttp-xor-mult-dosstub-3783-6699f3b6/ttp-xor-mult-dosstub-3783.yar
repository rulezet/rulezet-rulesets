rule TTP_XOR_MULT_DOSStub_3783 {
  strings:
    $key_3783 = { 63 eb [2] 17 f3 [2] 50 f1 [2] 17 e0 [2] 59 ec [2] 55 e6 [2] 42 ed [2] 59 a3 [2] 64 }

  condition:
    any of them
}