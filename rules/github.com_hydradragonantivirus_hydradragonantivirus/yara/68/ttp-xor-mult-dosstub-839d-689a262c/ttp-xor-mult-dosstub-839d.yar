rule TTP_XOR_MULT_DOSStub_839d {
  strings:
    $key_839d = { d7 f5 [2] a3 ed [2] e4 ef [2] a3 fe [2] ed f2 [2] e1 f8 [2] f6 f3 [2] ed bd [2] d0 }

  condition:
    any of them
}