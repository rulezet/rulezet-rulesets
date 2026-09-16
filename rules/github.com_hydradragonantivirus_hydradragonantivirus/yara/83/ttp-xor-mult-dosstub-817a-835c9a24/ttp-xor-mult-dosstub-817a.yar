rule TTP_XOR_MULT_DOSStub_817a {
  strings:
    $key_817a = { d5 12 [2] a1 0a [2] e6 08 [2] a1 19 [2] ef 15 [2] e3 1f [2] f4 14 [2] ef 5a [2] d2 }

  condition:
    any of them
}