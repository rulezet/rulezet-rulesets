rule TTP_XOR_MULT_DOSStub_909b {
  strings:
    $key_909b = { c4 f3 [2] b0 eb [2] f7 e9 [2] b0 f8 [2] fe f4 [2] f2 fe [2] e5 f5 [2] fe bb [2] c3 }

  condition:
    any of them
}