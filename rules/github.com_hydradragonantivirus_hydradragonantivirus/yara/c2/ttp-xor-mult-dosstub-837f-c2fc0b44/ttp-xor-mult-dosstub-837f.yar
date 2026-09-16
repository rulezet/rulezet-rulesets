rule TTP_XOR_MULT_DOSStub_837f {
  strings:
    $key_837f = { d7 17 [2] a3 0f [2] e4 0d [2] a3 1c [2] ed 10 [2] e1 1a [2] f6 11 [2] ed 5f [2] d0 }

  condition:
    any of them
}