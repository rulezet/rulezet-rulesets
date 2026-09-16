rule TTP_XOR_MULT_DOSStub_d340 {
  strings:
    $key_d340 = { 87 28 [2] f3 30 [2] b4 32 [2] f3 23 [2] bd 2f [2] b1 25 [2] a6 2e [2] bd 60 [2] 80 }

  condition:
    any of them
}