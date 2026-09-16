rule TTP_XOR_MULT_DOSStub_91e6 {
  strings:
    $key_91e6 = { c5 8e [2] b1 96 [2] f6 94 [2] b1 85 [2] ff 89 [2] f3 83 [2] e4 88 [2] ff c6 [2] c2 }

  condition:
    any of them
}