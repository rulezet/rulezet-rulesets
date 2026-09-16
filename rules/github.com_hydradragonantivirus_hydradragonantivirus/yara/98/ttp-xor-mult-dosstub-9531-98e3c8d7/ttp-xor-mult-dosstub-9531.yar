rule TTP_XOR_MULT_DOSStub_9531 {
  strings:
    $key_9531 = { c1 59 [2] b5 41 [2] f2 43 [2] b5 52 [2] fb 5e [2] f7 54 [2] e0 5f [2] fb 11 [2] c6 }

  condition:
    any of them
}