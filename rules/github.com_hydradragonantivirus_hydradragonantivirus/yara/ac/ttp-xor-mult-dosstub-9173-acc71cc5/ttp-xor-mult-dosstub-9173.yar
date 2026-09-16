rule TTP_XOR_MULT_DOSStub_9173 {
  strings:
    $key_9173 = { c5 1b [2] b1 03 [2] f6 01 [2] b1 10 [2] ff 1c [2] f3 16 [2] e4 1d [2] ff 53 [2] c2 }

  condition:
    any of them
}