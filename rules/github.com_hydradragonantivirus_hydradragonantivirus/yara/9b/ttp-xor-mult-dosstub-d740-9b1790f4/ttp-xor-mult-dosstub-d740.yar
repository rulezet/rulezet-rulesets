rule TTP_XOR_MULT_DOSStub_d740 {
  strings:
    $key_d740 = { 83 28 [2] f7 30 [2] b0 32 [2] f7 23 [2] b9 2f [2] b5 25 [2] a2 2e [2] b9 60 [2] 84 }

  condition:
    any of them
}