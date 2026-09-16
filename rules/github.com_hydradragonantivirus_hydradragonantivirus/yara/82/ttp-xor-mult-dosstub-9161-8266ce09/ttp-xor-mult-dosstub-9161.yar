rule TTP_XOR_MULT_DOSStub_9161 {
  strings:
    $key_9161 = { c5 09 [2] b1 11 [2] f6 13 [2] b1 02 [2] ff 0e [2] f3 04 [2] e4 0f [2] ff 41 [2] c2 }

  condition:
    any of them
}