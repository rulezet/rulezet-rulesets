rule TTP_XOR_MULT_DOSStub_819d {
  strings:
    $key_819d = { d5 f5 [2] a1 ed [2] e6 ef [2] a1 fe [2] ef f2 [2] e3 f8 [2] f4 f3 [2] ef bd [2] d2 }

  condition:
    any of them
}