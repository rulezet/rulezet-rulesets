rule TTP_XOR_MULT_DOSStub_839b {
  strings:
    $key_839b = { d7 f3 [2] a3 eb [2] e4 e9 [2] a3 f8 [2] ed f4 [2] e1 fe [2] f6 f5 [2] ed bb [2] d0 }

  condition:
    any of them
}