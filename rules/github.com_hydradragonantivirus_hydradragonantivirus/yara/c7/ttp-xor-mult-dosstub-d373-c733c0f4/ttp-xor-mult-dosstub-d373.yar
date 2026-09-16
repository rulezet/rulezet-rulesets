rule TTP_XOR_MULT_DOSStub_d373 {
  strings:
    $key_d373 = { 87 1b [2] f3 03 [2] b4 01 [2] f3 10 [2] bd 1c [2] b1 16 [2] a6 1d [2] bd 53 [2] 80 }

  condition:
    any of them
}