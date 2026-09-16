rule TTP_XOR_MULT_DOSStub_8103 {
  strings:
    $key_8103 = { d5 6b [2] a1 73 [2] e6 71 [2] a1 60 [2] ef 6c [2] e3 66 [2] f4 6d [2] ef 23 [2] d2 }

  condition:
    any of them
}