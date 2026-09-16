rule TTP_XOR_MULT_DOSStub_9671 {
  strings:
    $key_9671 = { c2 19 [2] b6 01 [2] f1 03 [2] b6 12 [2] f8 1e [2] f4 14 [2] e3 1f [2] f8 51 [2] c5 }

  condition:
    any of them
}