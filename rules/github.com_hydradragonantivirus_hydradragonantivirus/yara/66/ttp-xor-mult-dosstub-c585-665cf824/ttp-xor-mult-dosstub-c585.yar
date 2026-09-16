rule TTP_XOR_MULT_DOSStub_c585 {
  strings:
    $key_c585 = { 91 ed [2] e5 f5 [2] a2 f7 [2] e5 e6 [2] ab ea [2] a7 e0 [2] b0 eb [2] ab a5 [2] 96 }

  condition:
    any of them
}