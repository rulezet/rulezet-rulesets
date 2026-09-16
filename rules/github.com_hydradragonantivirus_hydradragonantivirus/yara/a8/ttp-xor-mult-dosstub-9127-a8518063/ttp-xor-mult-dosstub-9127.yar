rule TTP_XOR_MULT_DOSStub_9127 {
  strings:
    $key_9127 = { c5 4f [2] b1 57 [2] f6 55 [2] b1 44 [2] ff 48 [2] f3 42 [2] e4 49 [2] ff 07 [2] c2 }

  condition:
    any of them
}