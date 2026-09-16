rule TTP_XOR_MULT_DOSStub_9120 {
  strings:
    $key_9120 = { c5 48 [2] b1 50 [2] f6 52 [2] b1 43 [2] ff 4f [2] f3 45 [2] e4 4e [2] ff 00 [2] c2 }

  condition:
    any of them
}