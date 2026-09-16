rule TTP_XOR_MULT_DOSStub_9118 {
  strings:
    $key_9118 = { c5 70 [2] b1 68 [2] f6 6a [2] b1 7b [2] ff 77 [2] f3 7d [2] e4 76 [2] ff 38 [2] c2 }

  condition:
    any of them
}