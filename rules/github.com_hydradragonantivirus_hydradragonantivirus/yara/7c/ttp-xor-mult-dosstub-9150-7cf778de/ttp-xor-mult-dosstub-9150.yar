rule TTP_XOR_MULT_DOSStub_9150 {
  strings:
    $key_9150 = { c5 38 [2] b1 20 [2] f6 22 [2] b1 33 [2] ff 3f [2] f3 35 [2] e4 3e [2] ff 70 [2] c2 }

  condition:
    any of them
}