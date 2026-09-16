rule TTP_XOR_MULT_DOSStub_94d9 {
  strings:
    $key_94d9 = { c0 b1 [2] b4 a9 [2] f3 ab [2] b4 ba [2] fa b6 [2] f6 bc [2] e1 b7 [2] fa f9 [2] c7 }

  condition:
    any of them
}