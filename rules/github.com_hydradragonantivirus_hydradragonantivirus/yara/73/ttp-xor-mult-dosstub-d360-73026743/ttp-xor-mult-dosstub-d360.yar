rule TTP_XOR_MULT_DOSStub_d360 {
  strings:
    $key_d360 = { 87 08 [2] f3 10 [2] b4 12 [2] f3 03 [2] bd 0f [2] b1 05 [2] a6 0e [2] bd 40 [2] 80 }

  condition:
    any of them
}