rule TTP_XOR_MULT_DOSStub_9166 {
  strings:
    $key_9166 = { c5 0e [2] b1 16 [2] f6 14 [2] b1 05 [2] ff 09 [2] f3 03 [2] e4 08 [2] ff 46 [2] c2 }

  condition:
    any of them
}