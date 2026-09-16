rule TTP_XOR_MULT_DOSStub_d374 {
  strings:
    $key_d374 = { 87 1c [2] f3 04 [2] b4 06 [2] f3 17 [2] bd 1b [2] b1 11 [2] a6 1a [2] bd 54 [2] 80 }

  condition:
    any of them
}