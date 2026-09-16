rule TTP_XOR_MULT_DOSStub_d288 {
  strings:
    $key_d288 = { 86 e0 [2] f2 f8 [2] b5 fa [2] f2 eb [2] bc e7 [2] b0 ed [2] a7 e6 [2] bc a8 [2] 81 }

  condition:
    any of them
}