rule TTP_XOR_MULT_DOSStub_c584 {
  strings:
    $key_c584 = { 91 ec [2] e5 f4 [2] a2 f6 [2] e5 e7 [2] ab eb [2] a7 e1 [2] b0 ea [2] ab a4 [2] 96 }

  condition:
    any of them
}