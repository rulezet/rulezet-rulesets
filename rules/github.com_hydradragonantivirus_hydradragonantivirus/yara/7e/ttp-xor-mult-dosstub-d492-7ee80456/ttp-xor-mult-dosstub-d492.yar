rule TTP_XOR_MULT_DOSStub_d492 {
  strings:
    $key_d492 = { 80 fa [2] f4 e2 [2] b3 e0 [2] f4 f1 [2] ba fd [2] b6 f7 [2] a1 fc [2] ba b2 [2] 87 }

  condition:
    any of them
}