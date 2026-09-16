rule TTP_XOR_MULT_DOSStub_9162 {
  strings:
    $key_9162 = { c5 0a [2] b1 12 [2] f6 10 [2] b1 01 [2] ff 0d [2] f3 07 [2] e4 0c [2] ff 42 [2] c2 }

  condition:
    any of them
}