rule TTP_XOR_MULT_DOSStub_d494 {
  strings:
    $key_d494 = { 80 fc [2] f4 e4 [2] b3 e6 [2] f4 f7 [2] ba fb [2] b6 f1 [2] a1 fa [2] ba b4 [2] 87 }

  condition:
    any of them
}