rule TTP_XOR_MULT_DOSStub_9683 {
  strings:
    $key_9683 = { c2 eb [2] b6 f3 [2] f1 f1 [2] b6 e0 [2] f8 ec [2] f4 e6 [2] e3 ed [2] f8 a3 [2] c5 }

  condition:
    any of them
}