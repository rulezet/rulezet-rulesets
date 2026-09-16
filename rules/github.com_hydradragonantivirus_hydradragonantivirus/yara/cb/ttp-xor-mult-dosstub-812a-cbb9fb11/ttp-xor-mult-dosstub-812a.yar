rule TTP_XOR_MULT_DOSStub_812a {
  strings:
    $key_812a = { d5 42 [2] a1 5a [2] e6 58 [2] a1 49 [2] ef 45 [2] e3 4f [2] f4 44 [2] ef 0a [2] d2 }

  condition:
    any of them
}