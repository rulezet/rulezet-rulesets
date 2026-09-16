rule TTP_XOR_MULT_DOSStub_d283 {
  strings:
    $key_d283 = { 86 eb [2] f2 f3 [2] b5 f1 [2] f2 e0 [2] bc ec [2] b0 e6 [2] a7 ed [2] bc a3 [2] 81 }

  condition:
    any of them
}