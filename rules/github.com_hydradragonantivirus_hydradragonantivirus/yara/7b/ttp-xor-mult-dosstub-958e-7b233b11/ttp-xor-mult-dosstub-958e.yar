rule TTP_XOR_MULT_DOSStub_958e {
  strings:
    $key_958e = { c1 e6 [2] b5 fe [2] f2 fc [2] b5 ed [2] fb e1 [2] f7 eb [2] e0 e0 [2] fb ae [2] c6 }

  condition:
    any of them
}