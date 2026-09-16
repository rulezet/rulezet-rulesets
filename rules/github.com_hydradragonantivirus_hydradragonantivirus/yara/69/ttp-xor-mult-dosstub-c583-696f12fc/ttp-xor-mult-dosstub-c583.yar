rule TTP_XOR_MULT_DOSStub_c583 {
  strings:
    $key_c583 = { 91 eb [2] e5 f3 [2] a2 f1 [2] e5 e0 [2] ab ec [2] a7 e6 [2] b0 ed [2] ab a3 [2] 96 }

  condition:
    any of them
}