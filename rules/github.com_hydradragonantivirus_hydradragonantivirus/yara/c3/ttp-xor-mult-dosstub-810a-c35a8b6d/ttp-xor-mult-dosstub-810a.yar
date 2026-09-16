rule TTP_XOR_MULT_DOSStub_810a {
  strings:
    $key_810a = { d5 62 [2] a1 7a [2] e6 78 [2] a1 69 [2] ef 65 [2] e3 6f [2] f4 64 [2] ef 2a [2] d2 }

  condition:
    any of them
}