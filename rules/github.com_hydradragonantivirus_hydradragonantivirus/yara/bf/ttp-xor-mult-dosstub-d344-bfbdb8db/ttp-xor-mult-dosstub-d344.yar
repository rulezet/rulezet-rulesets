rule TTP_XOR_MULT_DOSStub_d344 {
  strings:
    $key_d344 = { 87 2c [2] f3 34 [2] b4 36 [2] f3 27 [2] bd 2b [2] b1 21 [2] a6 2a [2] bd 64 [2] 80 }

  condition:
    any of them
}