rule TTP_XOR_MULT_DOSStub_91f1 {
  strings:
    $key_91f1 = { c5 99 [2] b1 81 [2] f6 83 [2] b1 92 [2] ff 9e [2] f3 94 [2] e4 9f [2] ff d1 [2] c2 }

  condition:
    any of them
}