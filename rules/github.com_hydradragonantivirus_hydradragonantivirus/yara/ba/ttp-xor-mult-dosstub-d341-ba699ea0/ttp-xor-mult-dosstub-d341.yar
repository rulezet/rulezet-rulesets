rule TTP_XOR_MULT_DOSStub_d341 {
  strings:
    $key_d341 = { 87 29 [2] f3 31 [2] b4 33 [2] f3 22 [2] bd 2e [2] b1 24 [2] a6 2f [2] bd 61 [2] 80 }

  condition:
    any of them
}