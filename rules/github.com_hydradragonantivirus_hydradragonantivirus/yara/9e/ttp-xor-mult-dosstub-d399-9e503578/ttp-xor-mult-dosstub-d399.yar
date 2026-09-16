rule TTP_XOR_MULT_DOSStub_d399 {
  strings:
    $key_d399 = { 87 f1 [2] f3 e9 [2] b4 eb [2] f3 fa [2] bd f6 [2] b1 fc [2] a6 f7 [2] bd b9 [2] 80 }

  condition:
    any of them
}