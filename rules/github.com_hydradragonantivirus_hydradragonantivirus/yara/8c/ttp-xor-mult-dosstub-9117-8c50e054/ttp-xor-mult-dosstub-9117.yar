rule TTP_XOR_MULT_DOSStub_9117 {
  strings:
    $key_9117 = { c5 7f [2] b1 67 [2] f6 65 [2] b1 74 [2] ff 78 [2] f3 72 [2] e4 79 [2] ff 37 [2] c2 }

  condition:
    any of them
}