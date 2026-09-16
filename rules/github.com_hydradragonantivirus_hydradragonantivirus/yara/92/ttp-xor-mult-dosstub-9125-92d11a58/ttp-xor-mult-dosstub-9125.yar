rule TTP_XOR_MULT_DOSStub_9125 {
  strings:
    $key_9125 = { c5 4d [2] b1 55 [2] f6 57 [2] b1 46 [2] ff 4a [2] f3 40 [2] e4 4b [2] ff 05 [2] c2 }

  condition:
    any of them
}