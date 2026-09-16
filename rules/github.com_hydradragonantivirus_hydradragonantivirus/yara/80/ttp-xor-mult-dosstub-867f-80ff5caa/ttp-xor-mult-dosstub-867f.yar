rule TTP_XOR_MULT_DOSStub_867f {
  strings:
    $key_867f = { d2 17 [2] a6 0f [2] e1 0d [2] a6 1c [2] e8 10 [2] e4 1a [2] f3 11 [2] e8 5f [2] d5 }

  condition:
    any of them
}