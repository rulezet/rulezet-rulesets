rule TTP_XOR_MULT_DOSStub_9497 {
  strings:
    $key_9497 = { c0 ff [2] b4 e7 [2] f3 e5 [2] b4 f4 [2] fa f8 [2] f6 f2 [2] e1 f9 [2] fa b7 [2] c7 }

  condition:
    any of them
}