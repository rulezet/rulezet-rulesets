rule TTP_XOR_MULT_DOSStub_816a {
  strings:
    $key_816a = { d5 02 [2] a1 1a [2] e6 18 [2] a1 09 [2] ef 05 [2] e3 0f [2] f4 04 [2] ef 4a [2] d2 }

  condition:
    any of them
}