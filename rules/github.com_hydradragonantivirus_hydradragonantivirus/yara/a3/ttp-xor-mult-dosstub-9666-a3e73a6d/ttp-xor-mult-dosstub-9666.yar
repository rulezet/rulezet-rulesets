rule TTP_XOR_MULT_DOSStub_9666 {
  strings:
    $key_9666 = { c2 0e [2] b6 16 [2] f1 14 [2] b6 05 [2] f8 09 [2] f4 03 [2] e3 08 [2] f8 46 [2] c5 }

  condition:
    any of them
}