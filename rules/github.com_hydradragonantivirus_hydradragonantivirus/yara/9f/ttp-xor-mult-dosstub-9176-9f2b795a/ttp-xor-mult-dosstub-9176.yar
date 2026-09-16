rule TTP_XOR_MULT_DOSStub_9176 {
  strings:
    $key_9176 = { c5 1e [2] b1 06 [2] f6 04 [2] b1 15 [2] ff 19 [2] f3 13 [2] e4 18 [2] ff 56 [2] c2 }

  condition:
    any of them
}