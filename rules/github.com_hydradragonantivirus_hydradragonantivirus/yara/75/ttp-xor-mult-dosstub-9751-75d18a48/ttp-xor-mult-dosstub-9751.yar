rule TTP_XOR_MULT_DOSStub_9751 {
  strings:
    $key_9751 = { c3 39 [2] b7 21 [2] f0 23 [2] b7 32 [2] f9 3e [2] f5 34 [2] e2 3f [2] f9 71 [2] c4 }

  condition:
    any of them
}