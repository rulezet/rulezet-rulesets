rule TTP_XOR_MULT_DOSStub_811b {
  strings:
    $key_811b = { d5 73 [2] a1 6b [2] e6 69 [2] a1 78 [2] ef 74 [2] e3 7e [2] f4 75 [2] ef 3b [2] d2 }

  condition:
    any of them
}