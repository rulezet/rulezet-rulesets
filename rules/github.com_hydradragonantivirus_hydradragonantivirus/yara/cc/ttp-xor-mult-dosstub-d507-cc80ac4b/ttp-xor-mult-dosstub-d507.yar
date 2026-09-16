rule TTP_XOR_MULT_DOSStub_d507 {
  strings:
    $key_d507 = { 81 6f [2] f5 77 [2] b2 75 [2] f5 64 [2] bb 68 [2] b7 62 [2] a0 69 [2] bb 27 [2] 86 }

  condition:
    any of them
}