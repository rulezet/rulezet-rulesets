rule TTP_XOR_MULT_DOSStub_9160 {
  strings:
    $key_9160 = { c5 08 [2] b1 10 [2] f6 12 [2] b1 03 [2] ff 0f [2] f3 05 [2] e4 0e [2] ff 40 [2] c2 }

  condition:
    any of them
}