rule TTP_XOR_MULT_DOSStub_d300 {
  strings:
    $key_d300 = { 87 68 [2] f3 70 [2] b4 72 [2] f3 63 [2] bd 6f [2] b1 65 [2] a6 6e [2] bd 20 [2] 80 }

  condition:
    any of them
}