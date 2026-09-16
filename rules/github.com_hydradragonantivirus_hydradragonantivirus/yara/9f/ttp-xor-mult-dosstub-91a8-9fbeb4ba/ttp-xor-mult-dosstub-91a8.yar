rule TTP_XOR_MULT_DOSStub_91a8 {
  strings:
    $key_91a8 = { c5 c0 [2] b1 d8 [2] f6 da [2] b1 cb [2] ff c7 [2] f3 cd [2] e4 c6 [2] ff 88 [2] c2 }

  condition:
    any of them
}