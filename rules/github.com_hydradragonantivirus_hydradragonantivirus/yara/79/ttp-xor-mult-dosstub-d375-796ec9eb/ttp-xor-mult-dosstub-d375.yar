rule TTP_XOR_MULT_DOSStub_d375 {
  strings:
    $key_d375 = { 87 1d [2] f3 05 [2] b4 07 [2] f3 16 [2] bd 1a [2] b1 10 [2] a6 1b [2] bd 55 [2] 80 }

  condition:
    any of them
}