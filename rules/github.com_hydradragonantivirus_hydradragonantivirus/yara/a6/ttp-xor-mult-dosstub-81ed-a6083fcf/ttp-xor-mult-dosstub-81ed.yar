rule TTP_XOR_MULT_DOSStub_81ed {
  strings:
    $key_81ed = { d5 85 [2] a1 9d [2] e6 9f [2] a1 8e [2] ef 82 [2] e3 88 [2] f4 83 [2] ef cd [2] d2 }

  condition:
    any of them
}