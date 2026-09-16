rule TTP_XOR_MULT_DOSStub_d365 {
  strings:
    $key_d365 = { 87 0d [2] f3 15 [2] b4 17 [2] f3 06 [2] bd 0a [2] b1 00 [2] a6 0b [2] bd 45 [2] 80 }

  condition:
    any of them
}