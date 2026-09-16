rule TTP_XOR_MULT_DOSStub_9771 {
  strings:
    $key_9771 = { c3 19 [2] b7 01 [2] f0 03 [2] b7 12 [2] f9 1e [2] f5 14 [2] e2 1f [2] f9 51 [2] c4 }

  condition:
    any of them
}