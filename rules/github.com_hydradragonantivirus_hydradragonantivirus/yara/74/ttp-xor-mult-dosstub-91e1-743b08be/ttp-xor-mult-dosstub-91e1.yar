rule TTP_XOR_MULT_DOSStub_91e1 {
  strings:
    $key_91e1 = { c5 89 [2] b1 91 [2] f6 93 [2] b1 82 [2] ff 8e [2] f3 84 [2] e4 8f [2] ff c1 [2] c2 }

  condition:
    any of them
}