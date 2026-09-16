rule TTP_XOR_MULT_DOSStub_9520 {
  strings:
    $key_9520 = { c1 48 [2] b5 50 [2] f2 52 [2] b5 43 [2] fb 4f [2] f7 45 [2] e0 4e [2] fb 00 [2] c6 }

  condition:
    any of them
}