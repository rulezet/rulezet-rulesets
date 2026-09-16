rule TTP_XOR_MULT_DOSStub_862a {
  strings:
    $key_862a = { d2 42 [2] a6 5a [2] e1 58 [2] a6 49 [2] e8 45 [2] e4 4f [2] f3 44 [2] e8 0a [2] d5 }

  condition:
    any of them
}