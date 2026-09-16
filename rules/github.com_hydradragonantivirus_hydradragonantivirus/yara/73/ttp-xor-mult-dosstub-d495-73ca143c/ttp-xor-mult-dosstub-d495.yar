rule TTP_XOR_MULT_DOSStub_d495 {
  strings:
    $key_d495 = { 80 fd [2] f4 e5 [2] b3 e7 [2] f4 f6 [2] ba fa [2] b6 f0 [2] a1 fb [2] ba b5 [2] 87 }

  condition:
    any of them
}