rule TTP_XOR_MULT_DOSStub_8129 {
  strings:
    $key_8129 = { d5 41 [2] a1 59 [2] e6 5b [2] a1 4a [2] ef 46 [2] e3 4c [2] f4 47 [2] ef 09 [2] d2 }

  condition:
    any of them
}