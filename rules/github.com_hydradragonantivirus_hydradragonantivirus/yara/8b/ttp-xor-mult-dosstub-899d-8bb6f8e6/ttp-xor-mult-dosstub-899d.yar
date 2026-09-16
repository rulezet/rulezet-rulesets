rule TTP_XOR_MULT_DOSStub_899d {
  strings:
    $key_899d = { dd f5 [2] a9 ed [2] ee ef [2] a9 fe [2] e7 f2 [2] eb f8 [2] fc f3 [2] e7 bd [2] da }

  condition:
    any of them
}