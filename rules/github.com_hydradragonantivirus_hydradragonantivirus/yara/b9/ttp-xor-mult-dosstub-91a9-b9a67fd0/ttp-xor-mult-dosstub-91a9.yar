rule TTP_XOR_MULT_DOSStub_91a9 {
  strings:
    $key_91a9 = { c5 c1 [2] b1 d9 [2] f6 db [2] b1 ca [2] ff c6 [2] f3 cc [2] e4 c7 [2] ff 89 [2] c2 }

  condition:
    any of them
}