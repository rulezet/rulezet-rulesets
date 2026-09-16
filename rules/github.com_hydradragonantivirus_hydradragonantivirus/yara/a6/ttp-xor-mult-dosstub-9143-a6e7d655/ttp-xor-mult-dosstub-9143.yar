rule TTP_XOR_MULT_DOSStub_9143 {
  strings:
    $key_9143 = { c5 2b [2] b1 33 [2] f6 31 [2] b1 20 [2] ff 2c [2] f3 26 [2] e4 2d [2] ff 63 [2] c2 }

  condition:
    any of them
}