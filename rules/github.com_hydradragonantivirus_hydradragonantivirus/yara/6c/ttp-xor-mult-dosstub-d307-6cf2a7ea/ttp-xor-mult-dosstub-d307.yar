rule TTP_XOR_MULT_DOSStub_d307 {
  strings:
    $key_d307 = { 87 6f [2] f3 77 [2] b4 75 [2] f3 64 [2] bd 68 [2] b1 62 [2] a6 69 [2] bd 27 [2] 80 }

  condition:
    any of them
}