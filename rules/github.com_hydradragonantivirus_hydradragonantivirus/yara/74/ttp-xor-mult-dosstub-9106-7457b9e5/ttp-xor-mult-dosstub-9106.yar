rule TTP_XOR_MULT_DOSStub_9106 {
  strings:
    $key_9106 = { c5 6e [2] b1 76 [2] f6 74 [2] b1 65 [2] ff 69 [2] f3 63 [2] e4 68 [2] ff 26 [2] c2 }

  condition:
    any of them
}