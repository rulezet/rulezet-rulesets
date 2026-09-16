rule TTP_XOR_MULT_DOSStub_9102 {
  strings:
    $key_9102 = { c5 6a [2] b1 72 [2] f6 70 [2] b1 61 [2] ff 6d [2] f3 67 [2] e4 6c [2] ff 22 [2] c2 }

  condition:
    any of them
}