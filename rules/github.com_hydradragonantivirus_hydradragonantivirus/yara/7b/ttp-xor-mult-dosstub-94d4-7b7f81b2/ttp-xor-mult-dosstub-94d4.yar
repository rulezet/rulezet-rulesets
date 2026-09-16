rule TTP_XOR_MULT_DOSStub_94d4 {
  strings:
    $key_94d4 = { c0 bc [2] b4 a4 [2] f3 a6 [2] b4 b7 [2] fa bb [2] f6 b1 [2] e1 ba [2] fa f4 [2] c7 }

  condition:
    any of them
}