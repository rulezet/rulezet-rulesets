rule TTP_XOR_MULT_DOSStub_81fc {
  strings:
    $key_81fc = { d5 94 [2] a1 8c [2] e6 8e [2] a1 9f [2] ef 93 [2] e3 99 [2] f4 92 [2] ef dc [2] d2 }

  condition:
    any of them
}