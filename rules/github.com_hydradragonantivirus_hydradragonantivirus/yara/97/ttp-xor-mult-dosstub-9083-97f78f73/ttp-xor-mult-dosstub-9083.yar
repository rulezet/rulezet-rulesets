rule TTP_XOR_MULT_DOSStub_9083 {
  strings:
    $key_9083 = { c4 eb [2] b0 f3 [2] f7 f1 [2] b0 e0 [2] fe ec [2] f2 e6 [2] e5 ed [2] fe a3 [2] c3 }

  condition:
    any of them
}