rule TTP_XOR_MULT_DOSStub_9766 {
  strings:
    $key_9766 = { c3 0e [2] b7 16 [2] f0 14 [2] b7 05 [2] f9 09 [2] f5 03 [2] e2 08 [2] f9 46 [2] c4 }

  condition:
    any of them
}