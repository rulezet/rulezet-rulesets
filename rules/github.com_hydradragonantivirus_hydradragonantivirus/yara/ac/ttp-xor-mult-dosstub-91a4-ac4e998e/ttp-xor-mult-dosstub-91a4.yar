rule TTP_XOR_MULT_DOSStub_91a4 {
  strings:
    $key_91a4 = { c5 cc [2] b1 d4 [2] f6 d6 [2] b1 c7 [2] ff cb [2] f3 c1 [2] e4 ca [2] ff 84 [2] c2 }

  condition:
    any of them
}