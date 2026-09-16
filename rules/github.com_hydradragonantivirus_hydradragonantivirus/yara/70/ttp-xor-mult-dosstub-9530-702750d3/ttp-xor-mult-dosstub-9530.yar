rule TTP_XOR_MULT_DOSStub_9530 {
  strings:
    $key_9530 = { c1 58 [2] b5 40 [2] f2 42 [2] b5 53 [2] fb 5f [2] f7 55 [2] e0 5e [2] fb 10 [2] c6 }

  condition:
    any of them
}