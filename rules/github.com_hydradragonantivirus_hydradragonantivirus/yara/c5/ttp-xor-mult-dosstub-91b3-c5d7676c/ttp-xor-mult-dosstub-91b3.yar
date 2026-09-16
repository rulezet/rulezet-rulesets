rule TTP_XOR_MULT_DOSStub_91b3 {
  strings:
    $key_91b3 = { c5 db [2] b1 c3 [2] f6 c1 [2] b1 d0 [2] ff dc [2] f3 d6 [2] e4 dd [2] ff 93 [2] c2 }

  condition:
    any of them
}