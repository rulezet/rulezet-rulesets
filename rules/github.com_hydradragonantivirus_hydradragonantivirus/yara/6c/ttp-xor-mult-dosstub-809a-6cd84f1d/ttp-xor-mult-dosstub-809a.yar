rule TTP_XOR_MULT_DOSStub_809a {
  strings:
    $key_809a = { d4 f2 [2] a0 ea [2] e7 e8 [2] a0 f9 [2] ee f5 [2] e2 ff [2] f5 f4 [2] ee ba [2] d3 }

  condition:
    any of them
}