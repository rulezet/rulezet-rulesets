rule TTP_XOR_MULT_DOSStub_d378 {
  strings:
    $key_d378 = { 87 10 [2] f3 08 [2] b4 0a [2] f3 1b [2] bd 17 [2] b1 1d [2] a6 16 [2] bd 58 [2] 80 }

  condition:
    any of them
}