rule TTP_XOR_MULT_DOSStub_8517 {
  strings:
    $key_8517 = { d1 7f [2] a5 67 [2] e2 65 [2] a5 74 [2] eb 78 [2] e7 72 [2] f0 79 [2] eb 37 [2] d6 }

  condition:
    any of them
}