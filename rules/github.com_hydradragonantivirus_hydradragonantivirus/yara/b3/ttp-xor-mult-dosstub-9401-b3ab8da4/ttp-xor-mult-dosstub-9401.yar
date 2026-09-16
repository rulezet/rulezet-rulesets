rule TTP_XOR_MULT_DOSStub_9401 {
  strings:
    $key_9401 = { c0 69 [2] b4 71 [2] f3 73 [2] b4 62 [2] fa 6e [2] f6 64 [2] e1 6f [2] fa 21 [2] c7 }

  condition:
    any of them
}