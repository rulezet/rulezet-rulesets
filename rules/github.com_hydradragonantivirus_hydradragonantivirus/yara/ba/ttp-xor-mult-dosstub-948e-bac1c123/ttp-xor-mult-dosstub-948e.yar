rule TTP_XOR_MULT_DOSStub_948e {
  strings:
    $key_948e = { c0 e6 [2] b4 fe [2] f3 fc [2] b4 ed [2] fa e1 [2] f6 eb [2] e1 e0 [2] fa ae [2] c7 }

  condition:
    any of them
}