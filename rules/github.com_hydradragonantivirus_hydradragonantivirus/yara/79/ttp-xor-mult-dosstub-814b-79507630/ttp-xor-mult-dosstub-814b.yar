rule TTP_XOR_MULT_DOSStub_814b {
  strings:
    $key_814b = { d5 23 [2] a1 3b [2] e6 39 [2] a1 28 [2] ef 24 [2] e3 2e [2] f4 25 [2] ef 6b [2] d2 }

  condition:
    any of them
}