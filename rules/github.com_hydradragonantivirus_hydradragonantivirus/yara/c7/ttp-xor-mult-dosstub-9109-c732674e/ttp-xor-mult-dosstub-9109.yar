rule TTP_XOR_MULT_DOSStub_9109 {
  strings:
    $key_9109 = { c5 61 [2] b1 79 [2] f6 7b [2] b1 6a [2] ff 66 [2] f3 6c [2] e4 67 [2] ff 29 [2] c2 }

  condition:
    any of them
}