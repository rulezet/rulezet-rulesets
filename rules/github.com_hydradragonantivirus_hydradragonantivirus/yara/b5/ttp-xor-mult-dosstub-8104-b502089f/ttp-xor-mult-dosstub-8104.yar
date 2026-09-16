rule TTP_XOR_MULT_DOSStub_8104 {
  strings:
    $key_8104 = { d5 6c [2] a1 74 [2] e6 76 [2] a1 67 [2] ef 6b [2] e3 61 [2] f4 6a [2] ef 24 [2] d2 }

  condition:
    any of them
}