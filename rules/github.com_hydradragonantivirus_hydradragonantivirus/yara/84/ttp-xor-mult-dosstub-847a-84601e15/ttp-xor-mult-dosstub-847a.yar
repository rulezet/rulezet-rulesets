rule TTP_XOR_MULT_DOSStub_847a {
  strings:
    $key_847a = { d0 12 [2] a4 0a [2] e3 08 [2] a4 19 [2] ea 15 [2] e6 1f [2] f1 14 [2] ea 5a [2] d7 }

  condition:
    any of them
}